/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package kubelet

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/record"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
	"k8s.io/klog/v2"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/events"
	"k8s.io/kubernetes/pkg/kubelet/eviction"
	"k8s.io/kubernetes/pkg/kubelet/metrics"
	kubetypes "k8s.io/kubernetes/pkg/kubelet/types"
	"k8s.io/kubernetes/pkg/kubelet/util/queue"
)

// OnCompleteFunc is a function that is invoked when an operation completes.
// If err is non-nil, the operation did not complete successfully.
type OnCompleteFunc func(err error)

// PodStatusFunc is a function that is invoked to override the pod status when a pod is killed.
type PodStatusFunc func(podStatus *v1.PodStatus)

// KillPodOptions are options when performing a pod update whose update type is kill.
type KillPodOptions struct {
	// CompletedCh is closed when the kill request completes (syncTerminatingPod has completed
	// without error) or if the pod does not exist, or if the pod has already terminated. This
	// could take an arbitrary amount of time to be closed, but is never left open once
	// CouldHaveRunningContainers() returns false.
	CompletedCh chan<- struct{}
	// Evict is true if this is a pod triggered eviction - once a pod is evicted some resources are
	// more aggressively reaped than during normal pod operation (stopped containers).
	Evict         bool
	PodStatusFunc PodStatusFunc // 这个函数用于设置pod的终止消息
	// PodTerminationGracePeriodSecondsOverride is optional override to use if a pod is being killed as part of kill operation.
	PodTerminationGracePeriodSecondsOverride *int64
}

// UpdatePodOptions is an options struct to pass to a UpdatePod operation.
type UpdatePodOptions struct {
	UpdateType     kubetypes.SyncPodType // 更新类型（create, update, sync, kill）.
	StartTime      time.Time             // 是此更新创建的可选时间戳
	Pod            *v1.Pod               // 更新的 Pod
	MirrorPod      *v1.Pod               // 如果 Pod 是静态 Pod,则 MirrorPod 是镜像 Pod.当 UpdateType 为 kill 或 terminated 时可选.
	RunningPod     *kubecontainer.Pod    // 不再存在于配置中的运行时 Pod ..如果 Pod 为 nil,则必填,如果 Pod 已设置,则忽略.
	KillPodOptions *KillPodOptions       // 用于覆盖 Pod 的默认终止行为,或在操作完成后更新 Pod 状态.由于 Pod 可以因多种原因被终止,因此 PodStatusFunc 按顺序调用,后续的终止行为有机会覆盖状态（即,抢占可能会转变为驱逐）.
}

// PodWorkType 将pod生命周期的三个阶段分类 - 设置（同步）,容器的拆卸（终止）,清理（已终止）.
type PodWorkType int

const (
	// SyncPodWork is when the pod is expected to be started and running.
	SyncPodWork PodWorkType = iota
	// TerminatingPodWork is when the pod is no longer being set up, but some
	// containers may be running and are being torn down.
	TerminatingPodWork
	// TerminatedPodWork indicates the pod is stopped, can have no more running
	// containers, and any foreground cleanup can be executed.
	TerminatedPodWork
)

// PodWorkType classifies the status of pod as seen by the pod worker - setup (sync),
// teardown of containers (terminating), cleanup (terminated), or recreated with the
// same UID (kill -> create while terminating)
type PodWorkerState int

const (
	// SyncPod is when the pod is expected to be started and running.
	SyncPod PodWorkerState = iota
	// TerminatingPod is when the pod is no longer being set up, but some
	// containers may be running and are being torn down.
	TerminatingPod
	// TerminatedPod indicates the pod is stopped, can have no more running
	// containers, and any foreground cleanup can be executed.
	TerminatedPod
	// TerminatedAndRecreatedPod indicates that after the pod was terminating a
	// request to recreate the pod was received. The pod is terminated and can
	// now be restarted by sending a create event to the pod worker.
	TerminatedAndRecreatedPod
)

// podWork is the internal changes
type podWork struct {
	// WorkType is the type of sync to perform - sync (create), terminating (stop
	// containers), terminated (clean up and write status).
	WorkType PodWorkType

	// Options contains the data to sync.
	Options UpdatePodOptions
}

// PodWorkers is an abstract interface for testability.
type PodWorkers interface {

	// UpdatePod 通知pod worker有关pod的更改,然后每个pod UID的goroutine将按FIFO顺序处理.
	// pod的状态将传递给syncPod方法,直到pod被标记为已删除,达到终端阶段（已成功/已失败）或kubelet驱逐pod.
	// 一旦发生这种情况,将调用syncTerminatingPod方法,直到成功退出,之后所有进一步的UpdatePod（）调用将被忽略,直到由于时间过去而被遗忘.已终止的pod将永远不会重新启动.
	UpdatePod(options UpdatePodOptions)
	SyncKnownPods(desiredPods []*v1.Pod) map[types.UID]PodWorkerState // 删除不在 desiredPods 集合中且已经终止一段时间的 Pod 的工作器.
	IsPodKnownTerminated(uid types.UID) bool                          // pod是否被被完全终止
	// CouldHaveRunningContainers 确定是否可以在 Pod 上运行容器.如果 Pod 尚未同步,则可能会返回 true,因为尚未确定 Pod 的状态.
	// 如果 Pod 已同步,则可能会返回 true,因为 Pod 可能已经被调度到节点上,但尚未启动容器.
	// 如果 Pod 已终止,则返回 false,因为在这种情况下,所有容器都已停止.
	CouldHaveRunningContainers(uid types.UID) bool
	IsPodTerminationRequested(uid types.UID) bool // 判断 Pod 是否已经被请求终止,并且正在等待终止完成并从配置中删除.   kubelet的sync中使用

	// ShouldPodContainersBeTerminating returns false before pod workers have synced,
	// or once a pod has started terminating. This check is similar to
	// ShouldPodRuntimeBeRemoved but is also true after pod termination is requested.
	//
	// Intended for use by subsystem sync loops to avoid performing background setup
	// after termination has been requested for a pod. Callers must ensure that the
	// syncPod method is non-blocking when their data is absent.
	ShouldPodContainersBeTerminating(uid types.UID) bool
	// ShouldPodRuntimeBeRemoved returns true if runtime managers within the Kubelet
	// should aggressively cleanup pod resources that are not containers or on disk
	// content, like attached volumes. This is true when a pod is not yet observed
	// by a worker after the first sync (meaning it can't be running yet) or after
	// all running containers are stopped.
	// TODO: Once pod logs are separated from running containers, this method should
	// be used to gate whether containers are kept.
	//
	// Intended for use by subsystem sync loops to know when to start tearing down
	// resources that are used by running containers. Callers should ensure that
	// runtime content they own is not required for post-termination - for instance
	// containers are required in docker to preserve pod logs until after the pod
	// is deleted.
	ShouldPodRuntimeBeRemoved(uid types.UID) bool
	ShouldPodContentBeRemoved(uid types.UID) bool // 是不是应该删除 pod 相关的内容【正在删除的pod仍然可以被驱逐】
	// IsPodForMirrorPodTerminatingByFullName returns true if a static pod with the
	// provided pod name is currently terminating and has yet to complete. It is
	// intended to be used only during orphan mirror pod cleanup to prevent us from
	// deleting a terminating static pod from the apiserver before the pod is shut
	// down.
	IsPodForMirrorPodTerminatingByFullName(podFullname string) bool
}

// the function to invoke to perform a sync (reconcile the kubelet state to the desired shape of the pod)
type syncPodFnType func(ctx context.Context, updateType kubetypes.SyncPodType, pod *v1.Pod, mirrorPod *v1.Pod, podStatus *kubecontainer.PodStatus) (bool, error)

// 终止pod的调用函数（确保没有运行的进程存在）.
type syncTerminatingPodFnType func(ctx context.Context, pod *v1.Pod, podStatus *kubecontainer.PodStatus, runningPod *kubecontainer.Pod, gracePeriod *int64, podStatusFn func(*v1.PodStatus)) error

// 清理一个已经终止的pod资源
type syncTerminatedPodFnType func(ctx context.Context, pod *v1.Pod, podStatus *kubecontainer.PodStatus) error

const (
	// jitter factor for resyncInterval
	workerResyncIntervalJitterFactor = 0.5

	// jitter factor for backOffPeriod and backOffOnTransientErrorPeriod
	workerBackOffPeriodJitterFactor = 0.5

	// backoff period when transient error occurred.
	backOffOnTransientErrorPeriod = time.Second
)

// podSyncStatus tracks per-pod transitions through the three phases of pod
// worker sync (setup, terminating, terminated).
type podSyncStatus struct {
	// ctx is the context that is associated with the current pod sync.
	ctx context.Context
	// cancelFn if set is expected to cancel the current sync*Pod operation.
	cancelFn context.CancelFunc
	// working is true if a pod worker is currently in a sync method.
	working bool
	// fullname of the pod
	fullname string

	// syncedAt is the time at which the pod worker first observed this pod.
	syncedAt time.Time
	// terminatingAt is set once the pod is requested to be killed - note that
	// this can be set before the pod worker starts terminating the pod, see
	// terminating.
	terminatingAt time.Time
	// startedTerminating is true once the pod worker has observed the request to
	// stop a pod (exited syncPod and observed a podWork with WorkType
	// TerminatingPodWork). Once this is set, it is safe for other components
	// of the kubelet to assume that no other containers may be started.
	startedTerminating bool
	deleted            bool      // 如果pod已在apisserver上标记为删除,或者没有表示任何配置(之前已删除),则为true.
	gracePeriod        int64     // 优雅删除的时间
	evicted            bool      // 是不是被驱逐的
	terminatedAt       time.Time // 在pod worker成功完成syncTerminatingPod调用后设置,这意味着所有正在运行的容器都将停止.
	finished           bool      // 一旦pod worker完成pod的处理（syncTerminatedPod 无错误退出）,finished为true,直到调用SyncKnownPods以删除pod.终端pod（已成功/已失败）将具有终止状态,直到删除pod.
	restartRequested   bool      // 当 Pod 被杀死后,如果 restartRequested 为 true,则 kubelet 将尝试重新启动该 Pod.这通常是在更新类型为 create、update 或 sync 时发生的.

	// notifyPostTerminating will be closed once the pod transitions to
	// terminated. After the pod is in terminated state, nothing should be
	// added to this list.
	notifyPostTerminating []chan<- struct{}
	statusPostTerminating []PodStatusFunc // pod进入终止状态时会调用,只会调用最后一个
}

// podWorkers 追踪pod 在runtime中的状态
//
// 传递给pod worker的pod要么正在同步(预计正在运行),要么正在终止(有正在运行的容器,但预计不会启动新的容器),要么终止(没有正在运行的容器,但可能仍有资源正在消耗),要么正在清理(没有资源剩余).
// 一旦一个pod被设置为“拆除”,它就不能为该UID(对应于删除或驱逐)再次启动,直到:
//
//	1.pod worker完成(syncTerminatingPod和syncTerminatedPod按顺序退出,没有错误)
//	2.SyncKnownPods 方法由kubelet内务管理调用,并且该pod不是已知配置的一部分.
//
// Kubelet中的其他组件可以通过UpdatePod方法或killPodNow包装器请求终止pod -这将确保pod的组件被停止,直到Kubelet重新启动或永久(如果pod的阶段在pod状态更改中设置为终止阶段).
type podWorkers struct {
	podLock                   sync.Mutex                   //
	podsSynced                bool                         // 是否完整的同步过一次数据
	podUpdates                map[types.UID]chan podWork   // 跟踪所有正在运行的每个pod goroutine - 每个pod goroutine将通过其相应的通道处理接收到的更新.
	lastUndeliveredWorkUpdate map[types.UID]podWork        // 跟踪此pod的最后一个未传递的工作项 - 如果工作程序正在工作,则工作项未传递.
	podSyncStatuses           map[types.UID]*podSyncStatus // 通过UID跟踪pod的终止状态—同步、终止、终止和逐出.

	// Tracks all uids for started static pods by full name
	startedStaticPodsByFullname map[string]types.UID
	// Tracks all uids for static pods that are waiting to start by full name
	waitingToStartStaticPodsByFullname map[string][]types.UID

	workQueue queue.WorkQueue

	// This function is run to sync the desired state of pod.
	// NOTE: This function has to be thread-safe - it can be called for
	// different pods at the same time.

	syncPodFn            syncPodFnType
	syncTerminatingPodFn syncTerminatingPodFnType
	syncTerminatedPodFn  syncTerminatedPodFnType // pod终止完成后 调用的函数

	workerChannelFn func(uid types.UID, in chan podWork) (out <-chan podWork) // 钩子函数

	// The EventRecorder to use
	recorder record.EventRecorder

	// backOffPeriod is the duration to back off when there is a sync error.
	backOffPeriod time.Duration

	// resyncInterval is the duration to wait until the next sync.
	resyncInterval time.Duration

	// podCache stores kubecontainer.PodStatus for all pods.
	podCache kubecontainer.Cache
}

func newPodWorkers(
	syncPodFn syncPodFnType,
	syncTerminatingPodFn syncTerminatingPodFnType,
	syncTerminatedPodFn syncTerminatedPodFnType,
	recorder record.EventRecorder,
	workQueue queue.WorkQueue,
	resyncInterval, backOffPeriod time.Duration,
	podCache kubecontainer.Cache,
) PodWorkers {
	return &podWorkers{
		podSyncStatuses:                    map[types.UID]*podSyncStatus{},
		podUpdates:                         map[types.UID]chan podWork{},
		lastUndeliveredWorkUpdate:          map[types.UID]podWork{},
		startedStaticPodsByFullname:        map[string]types.UID{},
		waitingToStartStaticPodsByFullname: map[string][]types.UID{},
		syncPodFn:                          syncPodFn,
		syncTerminatingPodFn:               syncTerminatingPodFn,
		syncTerminatedPodFn:                syncTerminatedPodFn,
		recorder:                           recorder,
		workQueue:                          workQueue,
		resyncInterval:                     resyncInterval,
		backOffPeriod:                      backOffPeriod,
		podCache:                           podCache,
	}
}

func (p *podWorkers) CouldHaveRunningContainers(uid types.UID) bool {
	p.podLock.Lock()
	defer p.podLock.Unlock()
	if status, ok := p.podSyncStatuses[uid]; ok {
		return !status.IsTerminated()
	}
	// once all pods are synced, any pod without sync status is known to not be running.
	return !p.podsSynced
}

func (p *podWorkers) IsPodTerminationRequested(uid types.UID) bool {
	p.podLock.Lock()
	defer p.podLock.Unlock()
	if status, ok := p.podSyncStatuses[uid]; ok {
		// the pod may still be setting up at this point.
		return status.IsTerminationRequested()
	}
	// an unknown pod is considered not to be terminating (use ShouldPodContainersBeTerminating in
	// cleanup loops to avoid failing to cleanup pods that have already been removed from config)
	// 未知的pod被认为没有终止(在清理循环中使用ShouldPodContainersBeTerminating以避免无法清除已经从配置中删除的pod)
	return false
}

func (p *podWorkers) ShouldPodContainersBeTerminating(uid types.UID) bool {
	p.podLock.Lock()
	defer p.podLock.Unlock()
	if status, ok := p.podSyncStatuses[uid]; ok {
		// we wait until the pod worker goroutine observes the termination, which means syncPod will not
		// be executed again, which means no new containers can be started
		return status.IsTerminationStarted()
	}
	// once we've synced, if the pod isn't known to the workers we should be tearing them
	// down
	return p.podsSynced
}

func (p *podWorkers) ShouldPodRuntimeBeRemoved(uid types.UID) bool {
	p.podLock.Lock()
	defer p.podLock.Unlock()
	if status, ok := p.podSyncStatuses[uid]; ok {
		return status.IsTerminated()
	}
	// a pod that hasn't been sent to the pod worker yet should have no runtime components once we have
	// synced all content.
	return p.podsSynced
}

func (p *podWorkers) ShouldPodContentBeRemoved(uid types.UID) bool {
	// 是否应该删除 pod 数据
	p.podLock.Lock()
	defer p.podLock.Unlock()
	if status, ok := p.podSyncStatuses[uid]; ok {
		return status.IsEvicted() || (status.IsDeleted() && status.IsTerminated())
	}
	// a pod that hasn't been sent to the pod worker yet should have no content on disk once we have
	// synced all content.
	return p.podsSynced
}

func (p *podWorkers) IsPodForMirrorPodTerminatingByFullName(podFullName string) bool {
	p.podLock.Lock()
	defer p.podLock.Unlock()
	uid, started := p.startedStaticPodsByFullname[podFullName]
	if !started {
		return false
	}
	status, exists := p.podSyncStatuses[uid]
	if !exists {
		return false
	}
	if !status.IsTerminationRequested() || status.IsTerminated() {
		return false
	}

	return true
}

func isPodStatusCacheTerminal(status *kubecontainer.PodStatus) bool {
	runningContainers := 0
	runningSandboxes := 0
	for _, container := range status.ContainerStatuses {
		if container.State == kubecontainer.ContainerStateRunning {
			runningContainers++
		}
	}
	for _, sb := range status.SandboxStatuses {
		if sb.State == runtimeapi.PodSandboxState_SANDBOX_READY {
			runningSandboxes++
		}
	}
	return runningContainers == 0 && runningSandboxes == 0
}

// UpdatePod 将配置更改或终止状态传递给pod. ✅
// pod可以是可运行的、正在终止的或已终止的,如果在apiserver上删除,发现已到达终端阶段（已成功或已失败）,或者被kubelet驱逐,则会转换为终止状态.
func (p *podWorkers) UpdatePod(options UpdatePodOptions) {
	pod := options.Pod
	var isRuntimePod bool
	if options.RunningPod != nil {
		if options.Pod == nil {
			pod = options.RunningPod.ToAPIPod()
			if options.UpdateType != kubetypes.SyncPodKill {
				klog.InfoS("Pod update is ignored, runtime pods can only be killed", "pod", klog.KObj(pod), "podUID", pod.UID)
				return
			}
			options.Pod = pod
			isRuntimePod = true
		} else {
			options.RunningPod = nil
			klog.InfoS("Pod update included RunningPod which is only valid when Pod is not specified", "pod", klog.KObj(options.Pod), "podUID", options.Pod.UID)
		}
	}
	uid := pod.UID

	p.podLock.Lock()
	defer p.podLock.Unlock()

	// decide what to do with this pod - we are either setting it up, tearing it down, or ignoring it
	now := time.Now()
	status, ok := p.podSyncStatuses[uid]
	if !ok {
		klog.V(4).InfoS("Pod is being synced for the first time", "pod", klog.KObj(pod), "podUID", pod.UID)
		status = &podSyncStatus{
			syncedAt: now,
			fullname: kubecontainer.GetPodFullName(pod),
		}
		// 如果此pod正在第一次同步,则需要确保它是活动的pod.
		if !isRuntimePod && (pod.Status.Phase == v1.PodFailed || pod.Status.Phase == v1.PodSucceeded) {
			// 检查pod是否未运行且pod处于终止状态.
			// 如果成功,则在podWorker中记录它已终止.
			if statusCache, err := p.podCache.Get(pod.UID); err == nil {
				if isPodStatusCacheTerminal(statusCache) {
					status = &podSyncStatus{
						terminatedAt:       now,
						terminatingAt:      now,
						syncedAt:           now,
						startedTerminating: true,
						finished:           true,
						fullname:           kubecontainer.GetPodFullName(pod),
					}
				}
			}
		}
		p.podSyncStatuses[uid] = status
	}

	// if an update is received that implies the pod should be running, but we are already terminating a pod by
	// that UID, assume that two pods with the same UID were created in close temporal proximity (usually static
	// pod but it's possible for an apiserver to extremely rarely do something similar) - flag the sync status
	// to indicate that after the pod terminates it should be reset to "not running" to allow a subsequent add/update
	// to start the pod worker again
	if status.IsTerminationRequested() {
		if options.UpdateType == kubetypes.SyncPodCreate {
			status.restartRequested = true
			klog.V(4).InfoS("Pod is terminating but has been requested to restart with same UID, will be reconciled later", "pod", klog.KObj(pod), "podUID", pod.UID)
			return
		}
	}

	// once a pod is terminated by UID, it cannot reenter the pod worker (until the UID is purged by housekeeping)
	if status.IsFinished() {
		klog.V(4).InfoS("Pod is finished processing, no further updates", "pod", klog.KObj(pod), "podUID", pod.UID)
		return
	}

	// check for a transition to terminating
	var becameTerminating bool
	if !status.IsTerminationRequested() {
		switch {
		case isRuntimePod:
			klog.V(4).InfoS("Pod is orphaned and must be torn down", "pod", klog.KObj(pod), "podUID", pod.UID)
			status.deleted = true
			status.terminatingAt = now
			becameTerminating = true
		case pod.DeletionTimestamp != nil:
			klog.V(4).InfoS("Pod is marked for graceful deletion, begin teardown", "pod", klog.KObj(pod), "podUID", pod.UID)
			status.deleted = true
			status.terminatingAt = now
			becameTerminating = true
		case pod.Status.Phase == v1.PodFailed, pod.Status.Phase == v1.PodSucceeded:
			klog.V(4).InfoS("Pod is in a terminal phase (success/failed), begin teardown", "pod", klog.KObj(pod), "podUID", pod.UID)
			status.terminatingAt = now
			becameTerminating = true
		case options.UpdateType == kubetypes.SyncPodKill:
			if options.KillPodOptions != nil && options.KillPodOptions.Evict {
				klog.V(4).InfoS("Pod is being evicted by the kubelet, begin teardown", "pod", klog.KObj(pod), "podUID", pod.UID)
				status.evicted = true
			} else {
				klog.V(4).InfoS("Pod is being removed by the kubelet, begin teardown", "pod", klog.KObj(pod), "podUID", pod.UID)
			}
			status.terminatingAt = now
			becameTerminating = true
		}
	}

	// 一旦pod处于终止状态,所有更新都是kill操作,优雅期只能减少.
	var workType PodWorkType
	var wasGracePeriodShortened bool
	switch {
	case status.IsTerminated():
		// A terminated pod may still be waiting for cleanup - if we receive a runtime pod kill request
		// due to housekeeping seeing an older cached version of the runtime pod simply ignore it until
		// after the pod worker completes.
		if isRuntimePod {
			klog.V(3).InfoS("Pod is waiting for termination, ignoring runtime-only kill until after pod worker is fully terminated", "pod", klog.KObj(pod), "podUID", pod.UID)
			return
		}

		workType = TerminatedPodWork

		if options.KillPodOptions != nil {
			if ch := options.KillPodOptions.CompletedCh; ch != nil {
				close(ch)
			}
		}
		options.KillPodOptions = nil

	case status.IsTerminationRequested():
		workType = TerminatingPodWork
		if options.KillPodOptions == nil {
			options.KillPodOptions = &KillPodOptions{}
		}

		if ch := options.KillPodOptions.CompletedCh; ch != nil {
			status.notifyPostTerminating = append(status.notifyPostTerminating, ch)
		}
		if fn := options.KillPodOptions.PodStatusFunc; fn != nil {
			status.statusPostTerminating = append(status.statusPostTerminating, fn)
		}

		gracePeriod, gracePeriodShortened := calculateEffectiveGracePeriod(status, pod, options.KillPodOptions)

		wasGracePeriodShortened = gracePeriodShortened
		status.gracePeriod = gracePeriod
		// always set the grace period for syncTerminatingPod so we don't have to recalculate,
		// will never be zero.
		options.KillPodOptions.PodTerminationGracePeriodSecondsOverride = &gracePeriod

	default:
		workType = SyncPodWork

		// KillPodOptions is not valid for sync actions outside of the terminating phase
		if options.KillPodOptions != nil {
			if ch := options.KillPodOptions.CompletedCh; ch != nil {
				close(ch)
			}
			options.KillPodOptions = nil
		}
	}

	// the desired work we want to be performing
	work := podWork{
		WorkType: workType,
		Options:  options,
	}

	// start the pod worker goroutine if it doesn't exist
	podUpdates, exists := p.podUpdates[uid]
	if !exists {
		// 我们需要在这里有一个缓冲区,因为将更新放入通道的checkForUpdates（）方法从同一goroutine中调用,
		// 其中消耗通道.但是,可以保证在这种情况下通道为空,因此大小为1的缓冲区就足够了.
		podUpdates = make(chan podWork, 1)
		p.podUpdates[uid] = podUpdates

		// 确保静态pod按照它们由UpdatePod接收到的顺序启动.
		if kubetypes.IsStaticPod(pod) {
			p.waitingToStartStaticPodsByFullname[status.fullname] =
				append(p.waitingToStartStaticPodsByFullname[status.fullname], uid)
		}

		// allow testing of delays in the pod update channel
		var outCh <-chan podWork
		if p.workerChannelFn != nil {
			outCh = p.workerChannelFn(uid, podUpdates)
		} else {
			outCh = podUpdates
		}
		// 创建一个新的pod worker,意味着这是一个新的pod,或者kubelet刚刚重新启动.
		// 在任何情况下,kubelet都愿意相信第一个pod worker同步的pod状态.请参见syncPod中的相应注释.
		go func() {
			defer runtime.HandleCrash()
			p.managePodLoop(outCh) // ✈️
		}()
	}

	// 如果没有pod worker正在运行,则将请求分派给pod worker.
	if !status.IsWorking() {
		status.working = true
		podUpdates <- work // ✈️
		return
	}

	// 捕获请求更新和pod worker观察到更新之间的最大延迟.
	if undelivered, ok := p.lastUndeliveredWorkUpdate[pod.UID]; ok {
		// 跟踪请求配置更改和实现更改之间的最大延迟.
		// track the max latency between when a config change is requested and when it is realized
		if !undelivered.Options.StartTime.IsZero() && undelivered.Options.StartTime.Before(work.Options.StartTime) {
			work.Options.StartTime = undelivered.Options.StartTime
		}
	}

	// 始终同步最新的数据.
	p.lastUndeliveredWorkUpdate[pod.UID] = work

	if (becameTerminating || wasGracePeriodShortened) && status.cancelFn != nil {
		klog.V(3).InfoS("Cancelling current pod sync", "pod", klog.KObj(pod), "podUID", pod.UID, "updateType", work.WorkType)
		status.cancelFn()
		return
	}
}

// calculateEffectiveGracePeriod 为新的终止pod设置初始优雅期,或允许提供更短的优雅期,并返回所需的值.
func calculateEffectiveGracePeriod(status *podSyncStatus, pod *v1.Pod, options *KillPodOptions) (int64, bool) {
	// enforce the restriction that a grace period can only decrease and track whatever our value is,
	// then ensure a calculated value is passed down to lower levels
	gracePeriod := status.gracePeriod
	// this value is bedrock truth - the apiserver owns telling us this value calculated by apiserver
	if override := pod.DeletionGracePeriodSeconds; override != nil {
		if gracePeriod == 0 || *override < gracePeriod {
			gracePeriod = *override
		}
	}
	// we allow other parts of the kubelet (namely eviction) to request this pod be terminated faster
	if options != nil {
		if override := options.PodTerminationGracePeriodSecondsOverride; override != nil {
			if gracePeriod == 0 || *override < gracePeriod {
				gracePeriod = *override
			}
		}
	}
	// make a best effort to default this value to the pod's desired intent, in the event
	// the kubelet provided no requested value (graceful termination?)
	if gracePeriod == 0 && pod.Spec.TerminationGracePeriodSeconds != nil {
		gracePeriod = *pod.Spec.TerminationGracePeriodSeconds
	}
	// no matter what, we always supply a grace period of 1
	if gracePeriod < 1 {
		gracePeriod = 1
	}
	return gracePeriod, status.gracePeriod != 0 && status.gracePeriod != gracePeriod
}

// allowPodStart 是否允许pod启动
func (p *podWorkers) allowPodStart(pod *v1.Pod) (canStart bool, canEverStart bool) {
	if !kubetypes.IsStaticPod(pod) {
		// TODO: Do we want to allow non-static pods with the same full name?
		// Note that it may disable the force deletion of pods.
		return true, true
	}
	p.podLock.Lock()
	defer p.podLock.Unlock()
	status, ok := p.podSyncStatuses[pod.UID]
	if !ok {
		klog.ErrorS(nil, "Pod sync status does not exist, the worker should not be running", "pod", klog.KObj(pod), "podUID", pod.UID)
		return false, false
	}
	if status.IsTerminationRequested() {
		return false, false
	}
	if !p.allowStaticPodStart(status.fullname, pod.UID) { // 静态pod 等待一定时间,
		p.workQueue.Enqueue(pod.UID, wait.Jitter(p.backOffPeriod, workerBackOffPeriodJitterFactor))
		status.working = false
		return false, true
	}
	return true, true
}

// allowStaticPodStart tries to start the static pod and returns true if
// 1. there are no other started static pods with the same fullname
// 2. the uid matches that of the first valid static pod waiting to start
func (p *podWorkers) allowStaticPodStart(fullname string, uid types.UID) bool {
	startedUID, started := p.startedStaticPodsByFullname[fullname]
	if started {
		return startedUID == uid
	}

	waitingPods := p.waitingToStartStaticPodsByFullname[fullname]
	// TODO: This is O(N) with respect to the number of updates to static pods
	// with overlapping full names, and ideally would be O(1).
	for i, waitingUID := range waitingPods {
		// has pod already terminated or been deleted?
		status, ok := p.podSyncStatuses[waitingUID]
		if !ok || status.IsTerminationRequested() || status.IsTerminated() {
			continue
		}
		// another pod is next in line
		if waitingUID != uid {
			p.waitingToStartStaticPodsByFullname[fullname] = waitingPods[i:]
			return false
		}
		// we are up next, remove ourselves
		waitingPods = waitingPods[i+1:]
		break
	}
	if len(waitingPods) != 0 {
		p.waitingToStartStaticPodsByFullname[fullname] = waitingPods
	} else {
		delete(p.waitingToStartStaticPodsByFullname, fullname)
	}
	p.startedStaticPodsByFullname[fullname] = uid
	return true
}

// ✅
func (p *podWorkers) managePodLoop(podUpdates <-chan podWork) {
	var lastSyncTime time.Time
	var podStarted bool
	for update := range podUpdates {
		pod := update.Options.Pod

		// 决定是否启动pod.如果在允许启动pod之前终止了pod,则必须清理它,然后退出pod worker循环.
		if !podStarted {
			canStart, canEverStart := p.allowPodStart(pod)
			if !canEverStart {
				p.completeUnstartedTerminated(pod)
				start := update.Options.StartTime
				if !start.IsZero() {
					metrics.PodWorkerDuration.WithLabelValues("terminated").Observe(metrics.SinceInSeconds(start))
				}
				klog.V(4).InfoS("Processing pod event done", "pod", klog.KObj(pod), "podUID", pod.UID, "updateType", update.WorkType)
				return
			}
			if !canStart {
				klog.V(4).InfoS("Pod cannot start yet", "pod", klog.KObj(pod), "podUID", pod.UID)
				continue
			}
			podStarted = true
		}

		klog.V(4).InfoS("Processing pod event", "pod", klog.KObj(pod), "podUID", pod.UID, "updateType", update.WorkType)
		var isTerminal bool
		err := func() error {
			// worker负责确保同步方法在重新同步时看到适当的状态更新（最后一次同步的结果）,
			// 转换为终止状态（无等待时间）,或在终止时（最近的状态是什么）.
			// 只有同步和终止才能生成pod状态更改,而已终止的pod确保最近的状态传递到apiserver.
			var status *kubecontainer.PodStatus
			var err error
			switch {
			case update.Options.RunningPod != nil:
				// when we receive a running pod, we don't need status at all
			default:
				// wait until we see the next refresh from the PLEG via the cache (max 2s)
				// TODO: this adds ~1s of latency on all transitions from sync to terminating
				//  to terminated, and on all termination retries (including evictions). We should
				//  improve latency by making the pleg continuous and by allowing pod status
				//  changes to be refreshed when key events happen (killPod, sync->terminating).
				//  Improving this latency also reduces the possibility that a terminated
				//  container's status is garbage collected before we have a chance to update the
				//  API server (thus losing the exit code).
				status, err = p.podCache.GetNewerThan(pod.UID, lastSyncTime)
			}
			if err != nil {
				// This is the legacy event thrown by manage pod loop all other events are now dispatched
				// from syncPodFn
				p.recorder.Eventf(pod, v1.EventTypeWarning, events.FailedSync, "error determining status: %v", err)
				return err
			}

			ctx := p.contextForWorker(pod.UID)

			//
			switch {
			case update.WorkType == TerminatedPodWork:
				var _ = new(Kubelet).syncTerminatedPod
				err = p.syncTerminatedPodFn(ctx, pod, status)

			case update.WorkType == TerminatingPodWork:
				var gracePeriod *int64
				if opt := update.Options.KillPodOptions; opt != nil {
					gracePeriod = opt.PodTerminationGracePeriodSecondsOverride
				}
				podStatusFn := p.acknowledgeTerminating(pod) // ✅

				var _ = new(Kubelet).syncTerminatingPod
				err = p.syncTerminatingPodFn(ctx, pod, status, update.Options.RunningPod, gracePeriod, podStatusFn)

			default:
				isTerminal, err = p.syncPodFn(ctx, update.Options.UpdateType, pod, update.Options.MirrorPod, status)
			}

			lastSyncTime = time.Now()
			return err
		}()

		var phaseTransition bool
		switch {
		case err == context.Canceled:
			// when the context is cancelled we expect an update to already be queued
			klog.V(2).InfoS("Sync exited with context cancellation error", "pod", klog.KObj(pod), "podUID", pod.UID, "updateType", update.WorkType)

		case err != nil:
			// we will queue a retry
			klog.ErrorS(err, "Error syncing pod, skipping", "pod", klog.KObj(pod), "podUID", pod.UID)

		case update.WorkType == TerminatedPodWork:
			// we can shut down the worker
			p.completeTerminated(pod)
			if start := update.Options.StartTime; !start.IsZero() {
				metrics.PodWorkerDuration.WithLabelValues("terminated").Observe(metrics.SinceInSeconds(start))
			}
			klog.V(4).InfoS("Processing pod event done", "pod", klog.KObj(pod), "podUID", pod.UID, "updateType", update.WorkType)
			return

		case update.WorkType == TerminatingPodWork:
			// pods that don't exist in config don't need to be terminated, garbage collection will cover them
			if update.Options.RunningPod != nil {
				p.completeTerminatingRuntimePod(pod)
				if start := update.Options.StartTime; !start.IsZero() {
					metrics.PodWorkerDuration.WithLabelValues(update.Options.UpdateType.String()).Observe(metrics.SinceInSeconds(start))
				}
				klog.V(4).InfoS("Processing pod event done", "pod", klog.KObj(pod), "podUID", pod.UID, "updateType", update.WorkType)
				return
			}
			// 否则,我们进入终止阶段.
			p.completeTerminating(pod)
			phaseTransition = true

		case isTerminal:
			// if syncPod indicated we are now terminal, set the appropriate pod status to move to terminating
			klog.V(4).InfoS("Pod is terminal", "pod", klog.KObj(pod), "podUID", pod.UID, "updateType", update.WorkType)
			p.completeSync(pod)
			phaseTransition = true
		}

		// queue a retry if necessary, then put the next event in the channel if any
		p.completeWork(pod, phaseTransition, err)
		if start := update.Options.StartTime; !start.IsZero() {
			metrics.PodWorkerDuration.WithLabelValues(update.Options.UpdateType.String()).Observe(metrics.SinceInSeconds(start))
		}
		klog.V(4).InfoS("Processing pod event done", "pod", klog.KObj(pod), "podUID", pod.UID, "updateType", update.WorkType)
	}
}

// acknowledgeTerminating 承认终止状态
// 在pod worker看到终止状态时在pod状态上设置终止标志,以便其他组件知道不会在此pod中启动新容器.然后返回适用于此pod的状态函数（如果有）.
func (p *podWorkers) acknowledgeTerminating(pod *v1.Pod) PodStatusFunc {
	p.podLock.Lock()
	defer p.podLock.Unlock()

	status, ok := p.podSyncStatuses[pod.UID]
	if !ok {
		return nil
	}

	if !status.terminatingAt.IsZero() && !status.startedTerminating {
		klog.V(4).InfoS("Pod worker has observed request to terminate", "pod", klog.KObj(pod), "podUID", pod.UID)
		status.startedTerminating = true
	}

	if l := len(status.statusPostTerminating); l > 0 {
		return status.statusPostTerminating[l-1]
	}
	return nil
}

// completeSync is invoked when syncPod completes successfully and indicates the pod is now terminal and should
// be terminated. This happens when the natural pod lifecycle completes - any pod which is not RestartAlways
// exits. Unnatural completions, such as evictions, API driven deletion or phase transition, are handled by
// UpdatePod.
func (p *podWorkers) completeSync(pod *v1.Pod) {
	p.podLock.Lock()
	defer p.podLock.Unlock()

	klog.V(4).InfoS("Pod indicated lifecycle completed naturally and should now terminate", "pod", klog.KObj(pod), "podUID", pod.UID)

	if status, ok := p.podSyncStatuses[pod.UID]; ok {
		if status.terminatingAt.IsZero() {
			status.terminatingAt = time.Now()
		} else {
			klog.V(4).InfoS("Pod worker attempted to set terminatingAt twice, likely programmer error", "pod", klog.KObj(pod), "podUID", pod.UID)
		}
		status.startedTerminating = true
	}

	p.lastUndeliveredWorkUpdate[pod.UID] = podWork{
		WorkType: TerminatingPodWork,
		Options: UpdatePodOptions{
			Pod: pod,
		},
	}
}

// completeTerminating is invoked when syncTerminatingPod completes successfully, which means
// no container is running, no container will be started in the future, and we are ready for
// cleanup.  This updates the termination state which prevents future syncs and will ensure
// other kubelet loops know this pod is not running any containers.
func (p *podWorkers) completeTerminating(pod *v1.Pod) {
	p.podLock.Lock()
	defer p.podLock.Unlock()

	klog.V(4).InfoS("Pod terminated all containers successfully", "pod", klog.KObj(pod), "podUID", pod.UID)

	if status, ok := p.podSyncStatuses[pod.UID]; ok {
		if status.terminatingAt.IsZero() {
			klog.V(4).InfoS("Pod worker was terminated but did not have terminatingAt set, likely programmer error", "pod", klog.KObj(pod), "podUID", pod.UID)
		}
		status.terminatedAt = time.Now()
		for _, ch := range status.notifyPostTerminating {
			close(ch)
		}
		status.notifyPostTerminating = nil
		status.statusPostTerminating = nil
	}

	p.lastUndeliveredWorkUpdate[pod.UID] = podWork{
		WorkType: TerminatedPodWork,
		Options: UpdatePodOptions{
			Pod: pod,
		},
	}
}

// completeTerminatingRuntimePod is invoked when syncTerminatingPod completes successfully,
// which means an orphaned pod (no config) is terminated and we can exit. Since orphaned
// pods have no API representation, we want to exit the loop at this point
// cleanup.  This updates the termination state which prevents future syncs and will ensure
// other kubelet loops know this pod is not running any containers.
func (p *podWorkers) completeTerminatingRuntimePod(pod *v1.Pod) {
	p.podLock.Lock()
	defer p.podLock.Unlock()

	klog.V(4).InfoS("Pod terminated all orphaned containers successfully and worker can now stop", "pod", klog.KObj(pod), "podUID", pod.UID)

	if status, ok := p.podSyncStatuses[pod.UID]; ok {
		if status.terminatingAt.IsZero() {
			klog.V(4).InfoS("Pod worker was terminated but did not have terminatingAt set, likely programmer error", "pod", klog.KObj(pod), "podUID", pod.UID)
		}
		status.terminatedAt = time.Now()
		status.finished = true
		status.working = false

		if p.startedStaticPodsByFullname[status.fullname] == pod.UID {
			delete(p.startedStaticPodsByFullname, status.fullname)
		}
	}

	p.cleanupPodUpdates(pod.UID)
}

// completeTerminated is invoked after syncTerminatedPod completes successfully and means we
// can stop the pod worker. The pod is finalized at this point.
func (p *podWorkers) completeTerminated(pod *v1.Pod) {
	p.podLock.Lock()
	defer p.podLock.Unlock()

	klog.V(4).InfoS("Pod is complete and the worker can now stop", "pod", klog.KObj(pod), "podUID", pod.UID)

	p.cleanupPodUpdates(pod.UID)

	if status, ok := p.podSyncStatuses[pod.UID]; ok {
		if status.terminatingAt.IsZero() {
			klog.V(4).InfoS("Pod worker is complete but did not have terminatingAt set, likely programmer error", "pod", klog.KObj(pod), "podUID", pod.UID)
		}
		if status.terminatedAt.IsZero() {
			klog.V(4).InfoS("Pod worker is complete but did not have terminatedAt set, likely programmer error", "pod", klog.KObj(pod), "podUID", pod.UID)
		}
		status.finished = true
		status.working = false

		if p.startedStaticPodsByFullname[status.fullname] == pod.UID {
			delete(p.startedStaticPodsByFullname, status.fullname)
		}
	}
}

// completeUnstartedTerminated 如果尚未启动的pod在启动之前接收到终止信号,则调用该方法.
func (p *podWorkers) completeUnstartedTerminated(pod *v1.Pod) {
	p.podLock.Lock()
	defer p.podLock.Unlock()

	klog.V(4).InfoS("Pod never started and the worker can now stop", "pod", klog.KObj(pod), "podUID", pod.UID)

	p.cleanupPodUpdates(pod.UID)

	if status, ok := p.podSyncStatuses[pod.UID]; ok {
		if status.terminatingAt.IsZero() {
			klog.V(4).InfoS("Pod worker is complete but did not have terminatingAt set, likely programmer error", "pod", klog.KObj(pod), "podUID", pod.UID)
		}
		if !status.terminatedAt.IsZero() {
			klog.V(4).InfoS("Pod worker is complete and had terminatedAt set, likely programmer error", "pod", klog.KObj(pod), "podUID", pod.UID)
		}
		status.finished = true
		status.working = false
		status.terminatedAt = time.Now()

		if p.startedStaticPodsByFullname[status.fullname] == pod.UID {
			delete(p.startedStaticPodsByFullname, status.fullname)
		}
	}
}

// completeWork 在错误或下一个同步间隔上重新排队,然后立即执行任何待处理的工作.
func (p *podWorkers) completeWork(pod *v1.Pod, phaseTransition bool, syncErr error) {
	// Requeue the last update if the last sync returned error.
	switch {
	case phaseTransition:
		p.workQueue.Enqueue(pod.UID, 0)
	case syncErr == nil:
		// No error; requeue at the regular resync interval.
		p.workQueue.Enqueue(pod.UID, wait.Jitter(p.resyncInterval, workerResyncIntervalJitterFactor))
	case strings.Contains(syncErr.Error(), NetworkNotReadyErrorMsg):
		// Network is not ready; back off for short period of time and retry as network might be ready soon.
		p.workQueue.Enqueue(pod.UID, wait.Jitter(backOffOnTransientErrorPeriod, workerBackOffPeriodJitterFactor))
	default:
		// Error occurred during the sync; back off and then retry.
		p.workQueue.Enqueue(pod.UID, wait.Jitter(p.backOffPeriod, workerBackOffPeriodJitterFactor))
	}
	p.completeWorkQueueNext(pod.UID)
}

// completeWorkQueueNext 保持锁定状态,并将下一个工作项排队给工作程序,或清除工作状态.
func (p *podWorkers) completeWorkQueueNext(uid types.UID) {
	p.podLock.Lock()
	defer p.podLock.Unlock()
	if workUpdate, exists := p.lastUndeliveredWorkUpdate[uid]; exists {
		p.podUpdates[uid] <- workUpdate
		delete(p.lastUndeliveredWorkUpdate, uid)
	} else {
		p.podSyncStatuses[uid].working = false
	}
}

// contextForWorker returns or initializes the appropriate context for a known
// worker. If the current context is expired, it is reset. If no worker is
// present, no context is returned.
func (p *podWorkers) contextForWorker(uid types.UID) context.Context {
	p.podLock.Lock()
	defer p.podLock.Unlock()

	status, ok := p.podSyncStatuses[uid]
	if !ok {
		return nil
	}
	if status.ctx == nil || status.ctx.Err() == context.Canceled {
		status.ctx, status.cancelFn = context.WithCancel(context.Background())
	}
	return status.ctx
}

// SyncKnownPods will purge any fully terminated pods that are not in the desiredPods
// list, which means SyncKnownPods must be called in a threadsafe manner from calls
// to UpdatePods for new pods. It returns a map of known workers that are not finished
// with a value of SyncPodTerminated, SyncPodKill, or SyncPodSync depending on whether
// the pod is terminated, terminating, or syncing.
// 清除任何已完全终止且不在 desiredPods 列表中的 Pod.
func (p *podWorkers) SyncKnownPods(desiredPods []*v1.Pod) map[types.UID]PodWorkerState { // ✅
	workers := make(map[types.UID]PodWorkerState)
	known := make(map[types.UID]struct{})
	for _, pod := range desiredPods {
		known[pod.UID] = struct{}{}
	}

	p.podLock.Lock()
	defer p.podLock.Unlock()

	p.podsSynced = true
	for uid, status := range p.podSyncStatuses {
		if _, exists := known[uid]; !exists || status.restartRequested {
			p.removeTerminatedWorker(uid) // 任何已终止且具有 restartRequested 的 Pod 都将清除其历史记录.这是因为这些 Pod 已经被标记为需要重新启动,因此它们的历史记录不再需要保留.
		}
		switch {
		case !status.terminatedAt.IsZero():
			if status.restartRequested {
				workers[uid] = TerminatedAndRecreatedPod
			} else {
				workers[uid] = TerminatedPod
			}
		case !status.terminatingAt.IsZero():
			workers[uid] = TerminatingPod
		default:
			workers[uid] = SyncPod
		}
	}
	return workers
}

// removeTerminatedWorker cleans up and removes the worker status for a worker
// that has reached a terminal state of "finished" - has successfully exited
// syncTerminatedPod. This "forgets" a pod by UID and allows another pod to be
// recreated with the same UID.
func (p *podWorkers) removeTerminatedWorker(uid types.UID) { // ✅
	status, ok := p.podSyncStatuses[uid]
	if !ok {
		// already forgotten, or forgotten too early
		klog.V(4).InfoS("Pod worker has been requested for removal but is not a known pod", "podUID", uid)
		return
	}

	if !status.finished {
		klog.V(4).InfoS("Pod worker has been requested for removal but is still not fully terminated", "podUID", uid)
		return
	}

	if status.restartRequested {
		klog.V(4).InfoS("Pod has been terminated but another pod with the same UID was created, remove history to allow restart", "podUID", uid)
	} else {
		klog.V(4).InfoS("Pod has been terminated and is no longer known to the kubelet, remove all history", "podUID", uid)
	}
	delete(p.podSyncStatuses, uid)
	p.cleanupPodUpdates(uid)

	if p.startedStaticPodsByFullname[status.fullname] == uid {
		delete(p.startedStaticPodsByFullname, status.fullname)
	}
}

// killPodNow 返回一个KillPodFunc,可用于杀死pod.// 它旨在注入到需要杀死pod的其他模块中.
func killPodNow(podWorkers PodWorkers, recorder record.EventRecorder) eviction.KillPodFunc {
	return func(pod *v1.Pod, isEvicted bool, gracePeriodOverride *int64, statusFn func(*v1.PodStatus)) error {
		// 优雅杀死时的,等待时间
		gracePeriod := int64(0)
		if gracePeriodOverride != nil {
			gracePeriod = *gracePeriodOverride
		} else if pod.Spec.TerminationGracePeriodSeconds != nil {
			gracePeriod = *pod.Spec.TerminationGracePeriodSeconds
		}
		// 如果我们在合理的时间内没有收到回调,我们会超时并返回错误.
		//默认超时与优雅期相关（我们在10秒内等待kubelet->运行时流量完成以sigkill）
		timeout := int64(gracePeriod + (gracePeriod / 2))
		minTimeout := int64(10)
		if timeout < minTimeout {
			timeout = minTimeout
		}
		timeoutDuration := time.Duration(timeout) * time.Second

		// 打开一个通道,我们会阻塞等待结果.
		ch := make(chan struct{}, 1)
		podWorkers.UpdatePod(UpdatePodOptions{ // killPodNow
			Pod:        pod,
			UpdateType: kubetypes.SyncPodKill,
			KillPodOptions: &KillPodOptions{
				CompletedCh:                              ch,
				Evict:                                    isEvicted,
				PodStatusFunc:                            statusFn,
				PodTerminationGracePeriodSecondsOverride: gracePeriodOverride,
			},
		})

		// wait for either a response, or a timeout
		select {
		case <-ch:
			return nil
		case <-time.After(timeoutDuration):
			recorder.Eventf(pod, v1.EventTypeWarning, events.ExceededGracePeriod, "Container runtime did not kill the pod within specified grace period.")
			return fmt.Errorf("timeout waiting to kill pod")
		}
	}
}

// cleanupPodUpdates closes the podUpdates channel and removes it from
// podUpdates map so that the corresponding pod worker can stop. It also
// removes any undelivered work. This method must be called holding the
// pod lock.
func (p *podWorkers) cleanupPodUpdates(uid types.UID) {
	if ch, ok := p.podUpdates[uid]; ok {
		close(ch)
	}
	delete(p.podUpdates, uid)
	delete(p.lastUndeliveredWorkUpdate, uid)
}

// ----------------------------------------------------------------------------------------------------

func (p *podWorkers) IsPodKnownTerminated(uid types.UID) bool {
	p.podLock.Lock()
	defer p.podLock.Unlock()
	if status, ok := p.podSyncStatuses[uid]; ok {
		return status.IsTerminated()
	}
	// if the pod is not known, we return false (pod worker is not aware of it)
	return false
}

func (s *podSyncStatus) IsWorking() bool              { return s.working }
func (s *podSyncStatus) IsTerminationRequested() bool { return !s.terminatingAt.IsZero() }
func (s *podSyncStatus) IsTerminationStarted() bool   { return s.startedTerminating }
func (s *podSyncStatus) IsTerminated() bool           { return !s.terminatedAt.IsZero() }
func (s *podSyncStatus) IsFinished() bool             { return s.finished }
func (s *podSyncStatus) IsEvicted() bool              { return s.evicted }
func (s *podSyncStatus) IsDeleted() bool              { return s.deleted }
