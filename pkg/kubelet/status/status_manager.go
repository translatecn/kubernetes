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

//go:generate mockgen -source=status_manager.go -destination=testing/mock_pod_status_provider.go -package=testing PodStatusProvider
package status

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	clientset "k8s.io/client-go/kubernetes"

	v1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/apimachinery/pkg/util/wait"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/klog/v2"
	podutil "k8s.io/kubernetes/pkg/api/v1/pod"
	"k8s.io/kubernetes/pkg/features"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/metrics"
	kubepod "k8s.io/kubernetes/pkg/kubelet/pod"
	kubetypes "k8s.io/kubernetes/pkg/kubelet/types"
	statusutil "k8s.io/kubernetes/pkg/util/pod"
)

type PodStatusProvider interface {
	GetPodStatus(uid types.UID) (v1.PodStatus, bool) // bool 代表是否命中缓存
}

type PodDeletionSafetyProvider interface {
	PodResourcesAreReclaimed(pod *v1.Pod, status v1.PodStatus) bool // pod 是否可以安全删除
	PodCouldHaveRunningContainers(pod *v1.Pod) bool                 // pod是否有正在运行的容器
}

type PodStartupLatencyStateHelper interface {
	RecordStatusUpdated(pod *v1.Pod)
	DeletePodStartupState(podUID types.UID)
}

// Manager 接口是 kubelet Pod 状态的真实来源，应该随着最新的 v1.PodStatus 保持更新。它还将更新同步回 API 服务器。
type Manager interface {
	PodStatusProvider
	Start()                                                                                    // 启动API服务器状态同步循环。
	SetPodStatus(pod *v1.Pod, status v1.PodStatus)                                             // 更新给定 Pod 的缓存状态，并触发状态更新。
	SetContainerReadiness(podUID types.UID, containerID kubecontainer.ContainerID, ready bool) // 使用给定的 readiness 更新缓存的容器状态，并触发状态更新。
	SetContainerStartup(podUID types.UID, containerID kubecontainer.ContainerID, started bool) // 使用给定的 startup 更新缓存的容器状态，并触发状态更新。
	TerminatePod(pod *v1.Pod)                                                                  // 将提供的 Pod 的容器状态重置为终止状态，并触发状态更新。
	RemoveOrphanedStatuses(podUIDs map[types.UID]bool)                                         // 扫描状态缓存并删除未包含在提供的 podUIDs 中的 Pod 的任何条目。
}

// Updates pod statuses in apiserver. Writes only when new status has changed.
// All methods are thread-safe.'
// Manager 接口是 kubelet Pod 状态的真实来源，应该随着最新的 v1.PodStatus 保持更新。它还将更新同步回 API 服务器。
type manager struct {
	kubeClient              clientset.Interface               //
	podManager              kubepod.Manager                   // 用于管理 Pod 的管理器。
	podStatuses             map[types.UID]versionedPodStatus  // 从 Pod UID 到相应 Pod 同步状态的映射。它用于跟踪每个 Pod 的状态，并确保只在状态发生变化时写入 API 服务器。
	podStatusesLock         sync.RWMutex                      //
	podStatusChannel        chan podStatusSyncRequest         // 用于在状态变化时触发同步请求
	apiStatusVersions       map[kubetypes.MirrorPodUID]uint64 // 一个从Pod UID 到最新状态版本的映射，成功发送到 API 服务器。apiStatusVersions 只能从同步线程访问。# todo 是不是镜像、常规uid 都会记录
	podDeletionSafety       PodDeletionSafetyProvider         // 用于确保在删除 Pod 时不会丢失状态
	podStartupLatencyHelper PodStartupLatencyStateHelper      // 用于跟踪 Pod 启动延迟。
}

var _ Manager = &manager{}

// 是 v1.PodStatus 的包装器，包括一个版本号，用于强制确保不会向 API 服务器发送过期的 Pod 状态。
type versionedPodStatus struct {
	version      uint64       // 一个单调递增的版本号，用于跟踪 Pod 的状态版本。
	podName      string       //
	podNamespace string       //
	at           time.Time    // 最近更新的时间
	status       v1.PodStatus // 一个 v1.PodStatus 类型的变量，表示 要更新的Pod状态。
}

type podStatusSyncRequest struct {
	podUID types.UID
	status versionedPodStatus
}

const syncPeriod = 10 * time.Second

// NewManager returns a functional Manager.
func NewManager(
	kubeClient clientset.Interface,
	podManager kubepod.Manager,
	podDeletionSafety PodDeletionSafetyProvider,
	podStartupLatencyHelper PodStartupLatencyStateHelper,
) Manager {
	return &manager{
		kubeClient:              kubeClient,
		podManager:              podManager,
		podStatuses:             make(map[types.UID]versionedPodStatus),
		podStatusChannel:        make(chan podStatusSyncRequest, 1000), // Buffer up to 1000 statuses
		apiStatusVersions:       make(map[kubetypes.MirrorPodUID]uint64),
		podDeletionSafety:       podDeletionSafety,
		podStartupLatencyHelper: podStartupLatencyHelper,
	}
}

// isPodStatusByKubeletEqual returns true if the given pod statuses are equal when non-kubelet-owned
// pod conditions are excluded.
// This method normalizes the status before comparing so as to make sure that meaningless
// changes will be ignored.
func isPodStatusByKubeletEqual(oldStatus, status *v1.PodStatus) bool {
	oldCopy := oldStatus.DeepCopy()
	for _, c := range status.Conditions {
		// both owned and shared conditions are used for kubelet status equality
		if kubetypes.PodConditionByKubelet(c.Type) || kubetypes.PodConditionSharedByKubelet(c.Type) {
			_, oc := podutil.GetPodCondition(oldCopy, c.Type)
			if oc == nil || oc.Status != c.Status || oc.Message != c.Message || oc.Reason != c.Reason {
				return false
			}
		}
	}
	oldCopy.Conditions = status.Conditions
	return apiequality.Semantic.DeepEqual(oldCopy, status)
}

func findContainerStatus(status *v1.PodStatus, containerID string) (containerStatus *v1.ContainerStatus, init bool, ok bool) {
	// Find the container to update.
	for i, c := range status.ContainerStatuses {
		if c.ContainerID == containerID {
			return &status.ContainerStatuses[i], false, true
		}
	}

	for i, c := range status.InitContainerStatuses {
		if c.ContainerID == containerID {
			return &status.InitContainerStatuses[i], true, true
		}
	}

	return nil, false, false

}

// TerminatePod ensures that the status of containers is properly defaulted at the end of the pod
// lifecycle. As the Kubelet must reconcile with the container runtime to observe container status
// there is always the possibility we are unable to retrieve one or more container statuses due to
// garbage collection, admin action, or loss of temporary data on a restart. This method ensures
// that any absent container status is treated as a failure so that we do not incorrectly describe
// the pod as successful. If we have not yet initialized the pod in the presence of init containers,
// the init container failure status is sufficient to describe the pod as failing, and we do not need
// to override waiting containers (unless there is evidence the pod previously started those containers).

// hasPodInitialized returns true if the pod has no evidence of ever starting a regular container, which
// implies those containers should not be transitioned to terminated status.
func hasPodInitialized(pod *v1.Pod) bool {
	// a pod without init containers is always initialized
	if len(pod.Spec.InitContainers) == 0 {
		return true
	}
	// if any container has ever moved out of waiting state, the pod has initialized
	for _, status := range pod.Status.ContainerStatuses {
		if status.LastTerminationState.Terminated != nil || status.State.Waiting == nil {
			return true
		}
	}
	// if the last init container has ever completed with a zero exit code, the pod is initialized
	if l := len(pod.Status.InitContainerStatuses); l > 0 {
		container := pod.Status.InitContainerStatuses[l-1]
		if state := container.LastTerminationState; state.Terminated != nil && state.Terminated.ExitCode == 0 {
			return true
		}
		if state := container.State; state.Terminated != nil && state.Terminated.ExitCode == 0 {
			return true
		}
	}
	// otherwise the pod has no record of being initialized
	return false
}

// 返回除了处于等待状态的容器之外所有容器，等待状态的容器是那些已经尝试启动至少一次的容器。
// 如果所有容器都处于等待状态，则始终返回第一个容器。
func initializedContainers(containers []v1.ContainerStatus) []v1.ContainerStatus {
	for i := len(containers) - 1; i >= 0; i-- {
		// 重启之后
		if containers[i].State.Waiting == nil || containers[i].LastTerminationState.Terminated != nil {
			return containers[0 : i+1]
		}
	}
	// always return at least one container
	if len(containers) > 0 {
		return containers[0:1]
	}
	return nil
}

// syncPod 将给定的状态与API服务器同步。调用者不能持有锁。
func (m *manager) syncPod(uid types.UID, status versionedPodStatus) {
	//uid 是新的podID
	if !m.needsUpdate(uid, status) { // 不需要更新✅   ,版本后是旧的
		klog.V(1).InfoS("Status for oldPod is up-to-date; skipping", "podUID", uid)
		return
	}

	// TODO: make me easier to express from client code
	oldPod, err := m.kubeClient.CoreV1().Pods(status.podNamespace).Get(context.TODO(), status.podName, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		klog.V(3).InfoS("Pod does not exist on the server",
			"podUID", uid,
			"oldPod", klog.KRef(status.podNamespace, status.podName))
		// If the Pod is deleted the status will be cleared in
		// RemoveOrphanedStatuses, so we just ignore the update here.
		return
	}
	if err != nil {
		klog.InfoS("Failed to get status for oldPod",
			"podUID", uid,
			"oldPod", klog.KRef(status.podNamespace, status.podName),
			"err", err)
		return
	}
	// 返回 Pod 的实际 UID。如果 UID 属于镜像 Pod，则返回其静态 Pod 的 UID。否则，返回原始 UID。
	translatedUID := m.podManager.TranslatePodUID(oldPod.UID)
	// Type convert original uid just for the purpose of comparison.
	if len(translatedUID) > 0 && translatedUID != kubetypes.ResolvedPodUID(uid) {
		klog.V(2).InfoS("Pod被删除，然后重新创建，跳过状态更新",
			"oldPod", klog.KObj(oldPod),
			"oldPodUID", uid,
			"podUID", translatedUID)
		m.deletePodStatus(uid)
		return
	}

	mergedStatus := mergePodStatus(oldPod.Status, status.status, m.podDeletionSafety.PodCouldHaveRunningContainers(oldPod)) // ✅

	newPod, patchBytes, unchanged, err := statusutil.PatchPodStatus(context.TODO(), m.kubeClient, oldPod.Namespace, oldPod.Name, oldPod.UID, oldPod.Status, mergedStatus)
	klog.V(3).InfoS("Patch status for oldPod", "oldPod", klog.KObj(oldPod), "podUID", uid, "patch", string(patchBytes))

	if err != nil {
		klog.InfoS("Failed to update status for oldPod", "oldPod", klog.KObj(oldPod), "err", err)
		return
	}
	if unchanged {
		klog.V(3).InfoS("Status for oldPod is up-to-date", "oldPod", klog.KObj(oldPod), "statusVersion", status.version)
	} else {
		klog.V(3).InfoS("Status for oldPod updated successfully", "oldPod", klog.KObj(oldPod), "statusVersion", status.version, "status", mergedStatus)
		oldPod = newPod
		// We pass a new object (result of API call which contains updated ResourceVersion)
		m.podStartupLatencyHelper.RecordStatusUpdated(oldPod) // ✅
	}

	// measure how long the status update took to propagate from generation to update on the server
	if status.at.IsZero() {
		klog.V(3).InfoS("Pod had no status time set", "oldPod", klog.KObj(oldPod), "podUID", uid, "version", status.version)
	} else {
		duration := time.Now().Sub(status.at).Truncate(time.Millisecond)
		metrics.PodStatusSyncDuration.Observe(duration.Seconds())
	}

	m.apiStatusVersions[kubetypes.MirrorPodUID(oldPod.UID)] = status.version

	if m.canBeDeleted(oldPod, status.status) {
		// 常规pod的优雅删除。
		deleteOptions := metav1.DeleteOptions{
			GracePeriodSeconds: new(int64), // 立即
			//使用oldPod UID作为删除的前提条件，以防止删除新创建的具有相同名称和命名空间的oldPod。
			Preconditions: metav1.NewUIDPreconditions(string(oldPod.UID)),
		}
		err = m.kubeClient.CoreV1().Pods(oldPod.Namespace).Delete(context.TODO(), oldPod.Name, deleteOptions)
		if err != nil {
			klog.InfoS("Failed to delete status for oldPod", "oldPod", klog.KObj(oldPod), "err", err)
			return
		}
		klog.V(3).InfoS("Pod fully terminated and removed from etcd", "oldPod", klog.KObj(oldPod))
		m.deletePodStatus(uid)
	}
}

// needsReconcile compares the given status with the status in the pod manager (which
// in fact comes from apiserver), returns whether the status needs to be reconciled with
// the apiserver. Now when pod status is inconsistent between apiserver and kubelet,
// kubelet should forcibly send an update to reconcile the inconsistence, because kubelet
// should be the source of truth of pod status.
// NOTE(random-liu): It's simpler to pass in mirror pod uid and get mirror pod by uid, but
// now the pod manager only supports getting mirror pod by static pod, so we have to pass
// static pod uid here.
// TODO(random-liu): Simplify the logic when mirror pod manager is added.
func (m *manager) needsReconcile(uid types.UID, status v1.PodStatus) bool {
	// The pod could be a static pod, so we should translate first.
	pod, ok := m.podManager.GetPodByUID(uid)
	if !ok {
		klog.V(4).InfoS("Pod has been deleted, no need to reconcile", "podUID", string(uid))
		return false
	}
	// If the pod is a static pod, we should check its mirror pod, because only status in mirror pod is meaningful to us.
	if kubetypes.IsStaticPod(pod) {
		mirrorPod, ok := m.podManager.GetMirrorPodByPod(pod)
		if !ok {
			klog.V(4).InfoS("Static pod has no corresponding mirror pod, no need to reconcile", "pod", klog.KObj(pod))
			return false
		}
		pod = mirrorPod
	}

	podStatus := pod.Status.DeepCopy()
	normalizeStatus(pod, podStatus)

	if isPodStatusByKubeletEqual(podStatus, &status) {
		// If the status from the source is the same with the cached status,
		// reconcile is not needed. Just return.
		return false
	}
	klog.V(3).InfoS("Pod status is inconsistent with cached status for pod, a reconciliation should be triggered",
		"pod", klog.KObj(pod),
		"statusDiff", diff.ObjectDiff(podStatus, &status))

	return true
}

func (m *manager) TerminatePod(pod *v1.Pod) {
	m.podStatusesLock.Lock()
	defer m.podStatusesLock.Unlock()

	// ensure that all containers have a terminated state - because we do not know whether the container
	// was successful, always report an error
	oldStatus := &pod.Status
	if cachedStatus, ok := m.podStatuses[pod.UID]; ok {
		oldStatus = &cachedStatus.status
	}
	status := *oldStatus.DeepCopy()

	// once a pod has initialized, any missing status is treated as a failure
	if hasPodInitialized(pod) {
		for i := range status.ContainerStatuses {
			if status.ContainerStatuses[i].State.Terminated != nil {
				continue
			}
			status.ContainerStatuses[i].State = v1.ContainerState{
				Terminated: &v1.ContainerStateTerminated{
					Reason:   "ContainerStatusUnknown",
					Message:  "The container could not be located when the pod was terminated",
					ExitCode: 137,
				},
			}
		}
	}

	// all but the final suffix of init containers which have no evidence of a container start are
	// marked as failed containers
	for i := range initializedContainers(status.InitContainerStatuses) {
		if status.InitContainerStatuses[i].State.Terminated != nil {
			continue
		}
		status.InitContainerStatuses[i].State = v1.ContainerState{
			Terminated: &v1.ContainerStateTerminated{
				Reason:   "ContainerStatusUnknown",
				Message:  "The container could not be located when the pod was terminated",
				ExitCode: 137,
			},
		}
	}

	klog.V(5).InfoS("TerminatePod calling updateStatusInternal", "pod", klog.KObj(pod), "podUID", pod.UID)
	m.updateStatusInternal(pod, status, true) // ✅
}

// --------------------------------------------------------------------------------------------------------

// NeedToReconcilePodReadiness 检查 Pod 的就绪状态是否需要重新协调
// Pod 的就绪状态是指所有容器都已经启动并准备好接收流量。kubelet 组件会定期检查 Pod 的就绪状态，并与期望状态进行比较。
// 如果发现 Pod 的就绪状态与期望状态不一致，kubelet 组件会重新协调 Pod 的就绪状态，以确保其状态正确。
func NeedToReconcilePodReadiness(pod *v1.Pod) bool { // ✅
	if len(pod.Spec.ReadinessGates) == 0 {
		return false
	}
	podReadyCondition := GeneratePodReadyCondition( // ✅
		&pod.Spec,
		pod.Status.Conditions,
		pod.Status.ContainerStatuses,
		pod.Status.Phase,
	) // pod 是否ready, 以及没就绪的原因
	i, curCondition := podutil.GetPodConditionFromList(pod.Status.Conditions, v1.PodReady) // ✅
	// 有过ready状态，且是当前状态
	if i >= 0 && (curCondition.Status != podReadyCondition.Status || curCondition.Message != podReadyCondition.Message) {
		return true
	}
	return false
}

// ✅
func (m *manager) syncBatch() { // ✅
	var updatedStatuses []podStatusSyncRequest
	podToMirror, mirrorToPod := m.podManager.GetUIDTranslations()
	func() { // Critical section
		m.podStatusesLock.RLock()
		defer m.podStatusesLock.RUnlock()

		// Clean up orphaned versions.
		for uid := range m.apiStatusVersions {
			_, hasPod := m.podStatuses[types.UID(uid)]
			_, hasMirror := mirrorToPod[uid]
			if !hasPod && !hasMirror {
				delete(m.apiStatusVersions, uid)
			}
		}

		for uid, status := range m.podStatuses {
			syncedUID := kubetypes.MirrorPodUID(uid)
			if mirrorUID, ok := podToMirror[kubetypes.ResolvedPodUID(uid)]; ok {
				if mirrorUID == "" {
					klog.V(5).InfoS("Static pod does not have a corresponding mirror pod; skipping",
						"podUID", uid,
						"pod", klog.KRef(status.podNamespace, status.podName))
					continue
				}
				syncedUID = mirrorUID
			}
			if m.needsUpdate(types.UID(syncedUID), status) {
				updatedStatuses = append(updatedStatuses, podStatusSyncRequest{uid, status})
			} else if m.needsReconcile(uid, status.status) { // 通知
				// Delete the apiStatusVersions here to force an update on the pod status
				// In most cases the deleted apiStatusVersions here should be filled
				// soon after the following syncPod() [If the syncPod() sync an update
				// successfully].
				delete(m.apiStatusVersions, syncedUID)
				updatedStatuses = append(updatedStatuses, podStatusSyncRequest{uid, status})
			}
		}
	}()

	for _, update := range updatedStatuses {
		klog.V(5).InfoS("Status Manager: syncPod in syncbatch", "podUID", update.podUID)
		m.syncPod(update.podUID, update.status)
	}
}

// normalizes nanosecond precision timestamps in podStatus
// down to second precision (*RFC339NANO* -> *RFC3339*). This must be done
// before comparing podStatus to the status returned by apiserver because
// apiserver does not support RFC339NANO.
// Related issue #15262/PR #15263 to move apiserver to RFC339NANO is closed.
// 改一下时间格式
func normalizeStatus(pod *v1.Pod, status *v1.PodStatus) *v1.PodStatus {
	bytesPerStatus := kubecontainer.MaxPodTerminationMessageLogLength
	if containers := len(pod.Spec.Containers) + len(pod.Spec.InitContainers); containers > 0 {
		bytesPerStatus = bytesPerStatus / containers
	}
	normalizeTimeStamp := func(t *metav1.Time) {
		*t = t.Rfc3339Copy()
	}
	normalizeContainerState := func(c *v1.ContainerState) {
		if c.Running != nil {
			normalizeTimeStamp(&c.Running.StartedAt)
		}
		if c.Terminated != nil {
			normalizeTimeStamp(&c.Terminated.StartedAt)
			normalizeTimeStamp(&c.Terminated.FinishedAt)
			if len(c.Terminated.Message) > bytesPerStatus {
				c.Terminated.Message = c.Terminated.Message[:bytesPerStatus]
			}
		}
	}

	if status.StartTime != nil {
		normalizeTimeStamp(status.StartTime)
	}
	for i := range status.Conditions {
		condition := &status.Conditions[i]
		normalizeTimeStamp(&condition.LastProbeTime)
		normalizeTimeStamp(&condition.LastTransitionTime)
	}

	// update container statuses
	for i := range status.ContainerStatuses {
		cstatus := &status.ContainerStatuses[i]
		normalizeContainerState(&cstatus.State)
		normalizeContainerState(&cstatus.LastTerminationState)
	}
	// Sort the container statuses, so that the order won't affect the result of comparison
	sort.Sort(kubetypes.SortedContainerStatuses(status.ContainerStatuses))

	// update init container statuses
	for i := range status.InitContainerStatuses {
		cstatus := &status.InitContainerStatuses[i]
		normalizeContainerState(&cstatus.State)
		normalizeContainerState(&cstatus.LastTerminationState)
	}
	// Sort the container statuses, so that the order won't affect the result of comparison
	kubetypes.SortInitContainerStatuses(pod, status.InitContainerStatuses)
	return status
}

// 确保没有容器从 terminated向 non-terminated 状态转换
func checkContainerStateTransition(oldStatuses, newStatuses []v1.ContainerStatus, restartPolicy v1.RestartPolicy) error { // ✅
	// If we should always restart, containers are allowed to leave the terminated state
	if restartPolicy == v1.RestartPolicyAlways {
		return nil
	}
	for _, oldStatus := range oldStatuses {
		// Skip any container that wasn't terminated
		if oldStatus.State.Terminated == nil {
			continue
		}
		// Skip any container that failed but is allowed to restart
		if oldStatus.State.Terminated.ExitCode != 0 && restartPolicy == v1.RestartPolicyOnFailure {
			continue
		}
		for _, newStatus := range newStatuses {
			// 容器的名称
			if oldStatus.Name == newStatus.Name && newStatus.State.Terminated == nil {
				return fmt.Errorf("terminated container %v attempted illegal transition to non-terminated state", newStatus.Name)
			}
		}
	}
	return nil
}

// TODO(filipg): It'd be cleaner if we can do this without signal from user.
func (m *manager) RemoveOrphanedStatuses(podUIDs map[types.UID]bool) {
	m.podStatusesLock.Lock()
	defer m.podStatusesLock.Unlock()
	for key := range m.podStatuses {
		if _, ok := podUIDs[key]; !ok {
			klog.V(5).InfoS("Removing pod from status map.", "podUID", key)
			delete(m.podStatuses, key)
		}
	}
}

func updateLastTransitionTime(status, oldStatus *v1.PodStatus, conditionType v1.PodConditionType) { // ✅
	_, condition := podutil.GetPodCondition(status, conditionType)
	if condition == nil {
		return
	}
	// Need to set LastTransitionTime.
	lastTransitionTime := metav1.Now()
	_, oldCondition := podutil.GetPodCondition(oldStatus, conditionType)
	if oldCondition != nil && condition.Status == oldCondition.Status {
		lastTransitionTime = oldCondition.LastTransitionTime
	}
	condition.LastTransitionTime = lastTransitionTime
}

// ✅
func (m *manager) updateStatusInternal(pod *v1.Pod, status v1.PodStatus, forceUpdate bool) bool { // 返回是否更新 ✅
	var oldStatus v1.PodStatus
	cachedStatus, isCached := m.podStatuses[pod.UID]
	if isCached {
		oldStatus = cachedStatus.status
	} else if mirrorPod, ok := m.podManager.GetMirrorPodByPod(pod); ok {
		oldStatus = mirrorPod.Status
	} else {
		oldStatus = pod.Status
	}

	// 确保没有容器从 terminated向 non-terminated 状态转换
	if err := checkContainerStateTransition(oldStatus.ContainerStatuses, status.ContainerStatuses, pod.Spec.RestartPolicy); err != nil {
		klog.ErrorS(err, "Status update on pod aborted", "pod", klog.KObj(pod))
		return false
	}
	if err := checkContainerStateTransition(oldStatus.InitContainerStatuses, status.InitContainerStatuses, pod.Spec.RestartPolicy); err != nil {
		klog.ErrorS(err, "Status update on pod aborted", "pod", klog.KObj(pod))
		return false
	}
	// 存储了每种类型的缓存数据
	updateLastTransitionTime(&status, &oldStatus, v1.ContainersReady)      // ✅
	updateLastTransitionTime(&status, &oldStatus, v1.PodReady)             // ✅
	updateLastTransitionTime(&status, &oldStatus, v1.PodInitialized)       // ✅
	updateLastTransitionTime(&status, &oldStatus, kubetypes.PodHasNetwork) // ✅
	updateLastTransitionTime(&status, &oldStatus, v1.PodScheduled)         // ✅

	if utilfeature.DefaultFeatureGate.Enabled(features.PodDisruptionConditions) { // ✅
		updateLastTransitionTime(&status, &oldStatus, v1.DisruptionTarget) // ✅
	}

	// ensure that the start time does not change across updates.
	if oldStatus.StartTime != nil && !oldStatus.StartTime.IsZero() {
		status.StartTime = oldStatus.StartTime
	} else if status.StartTime.IsZero() {
		// if the status has no start time, we need to set an initial time
		now := metav1.Now()
		status.StartTime = &now
	}

	normalizeStatus(pod, &status) // 改一下时间格式

	// Perform some more extensive logging of container termination state to assist in
	// debugging production races (generally not needed).
	if klogV := klog.V(5); klogV.Enabled() {
		var containers []string
		for _, s := range append(append([]v1.ContainerStatus(nil), status.InitContainerStatuses...), status.ContainerStatuses...) {
			var current, previous string
			switch {
			case s.State.Running != nil:
				current = "running"
			case s.State.Waiting != nil:
				current = "waiting"
			case s.State.Terminated != nil:
				current = fmt.Sprintf("terminated=%d", s.State.Terminated.ExitCode)
			default:
				current = "unknown"
			}
			switch {
			case s.LastTerminationState.Running != nil:
				previous = "running"
			case s.LastTerminationState.Waiting != nil:
				previous = "waiting"
			case s.LastTerminationState.Terminated != nil:
				previous = fmt.Sprintf("terminated=%d", s.LastTerminationState.Terminated.ExitCode)
			default:
				previous = "<none>"
			}
			containers = append(containers, fmt.Sprintf("(%s state=%s previous=%s)", s.Name, current, previous))
		}
		sort.Strings(containers)
		klogV.InfoS("updateStatusInternal", "version", cachedStatus.version+1, "pod", klog.KObj(pod), "podUID", pod.UID, "containers", strings.Join(containers, " "))
	}

	// 这样做的目的是为了防止并发更新pod状态时互相干扰，从而使pod的阶段单调地进行。
	if isCached && isPodStatusByKubeletEqual(&cachedStatus.status, &status) && !forceUpdate {
		klog.V(3).InfoS("Ignoring same status for pod", "pod", klog.KObj(pod), "status", status)
		return false // No new status.
	}

	newStatus := versionedPodStatus{
		status:       status,
		version:      cachedStatus.version + 1,
		podName:      pod.Name,
		podNamespace: pod.Namespace,
	}

	// Multiple status updates can be generated before we update the API server,
	// so we track the time from the first status update until we retire it to
	// the API.
	if cachedStatus.at.IsZero() {
		newStatus.at = time.Now()
	} else {
		newStatus.at = cachedStatus.at
	}

	m.podStatuses[pod.UID] = newStatus

	select {
	case m.podStatusChannel <- podStatusSyncRequest{pod.UID, newStatus}:
		klog.V(5).InfoS("Status Manager: adding pod with new status to podStatusChannel",
			"pod", klog.KObj(pod),
			"podUID", pod.UID,
			"statusVersion", newStatus.version,
			"status", newStatus.status)
		return true
	default:
		// Let the periodic syncBatch handle the update if the channel is full.
		// We can't block, since we hold the mutex lock.
		klog.V(4).InfoS("Skipping the status update for pod for now because the channel is full",
			"pod", klog.KObj(pod),
			"status", status)
		return false
	}
}

// SetPodStatus 缓存更新给定pod的缓存状态,并触发状态更新.
func (m *manager) SetPodStatus(pod *v1.Pod, status v1.PodStatus) {
	m.podStatusesLock.Lock()
	defer m.podStatusesLock.Unlock()

	status = *status.DeepCopy()
	// 如果设置了删除时间戳,则强制进行状态更新.
	// 这是必要的,因为如果pod处于非运行状态,则仍需要能够触发更新和/或删除的pod worker.
	m.updateStatusInternal(pod, status, pod.DeletionTimestamp != nil) // ✅
}

func (m *manager) SetContainerReadiness(podUID types.UID, containerID kubecontainer.ContainerID, ready bool) {
	m.podStatusesLock.Lock()
	defer m.podStatusesLock.Unlock()

	pod, ok := m.podManager.GetPodByUID(podUID)
	if !ok {
		klog.V(4).InfoS("Pod has been deleted, no need to update readiness", "podUID", string(podUID))
		return
	}

	oldStatus, found := m.podStatuses[pod.UID]
	if !found {
		klog.InfoS("Container readiness changed before pod has synced",
			"pod", klog.KObj(pod),
			"containerID", containerID.String())
		return
	}

	// Find the container to update.
	containerStatus, _, ok := findContainerStatus(&oldStatus.status, containerID.String())
	if !ok {
		klog.InfoS("Container readiness changed for unknown container",
			"pod", klog.KObj(pod),
			"containerID", containerID.String())
		return
	}

	if containerStatus.Ready == ready {
		klog.V(4).InfoS("Container readiness unchanged",
			"ready", ready,
			"pod", klog.KObj(pod),
			"containerID", containerID.String())
		return
	}

	// Make sure we're not updating the cached version.
	status := *oldStatus.status.DeepCopy()
	containerStatus, _, _ = findContainerStatus(&status, containerID.String())
	containerStatus.Ready = ready

	// updateConditionFunc updates the corresponding type of condition
	updateConditionFunc := func(conditionType v1.PodConditionType, condition v1.PodCondition) {
		conditionIndex := -1
		for i, condition := range status.Conditions {
			if condition.Type == conditionType {
				conditionIndex = i
				break
			}
		}
		if conditionIndex != -1 {
			status.Conditions[conditionIndex] = condition
		} else {
			klog.InfoS("PodStatus missing condition type", "conditionType", conditionType, "status", status)
			status.Conditions = append(status.Conditions, condition)
		}
	}
	updateConditionFunc(v1.PodReady, GeneratePodReadyCondition(&pod.Spec, status.Conditions, status.ContainerStatuses, status.Phase))
	updateConditionFunc(v1.ContainersReady, GenerateContainersReadyCondition(&pod.Spec, status.ContainerStatuses, status.Phase))
	m.updateStatusInternal(pod, status, false) // ✅
}
func (m *manager) SetContainerStartup(podUID types.UID, containerID kubecontainer.ContainerID, started bool) {
	m.podStatusesLock.Lock()
	defer m.podStatusesLock.Unlock()

	pod, ok := m.podManager.GetPodByUID(podUID)
	if !ok {
		klog.V(4).InfoS("Pod has been deleted, no need to update startup", "podUID", string(podUID))
		return
	}

	oldStatus, found := m.podStatuses[pod.UID]
	if !found {
		klog.InfoS("Container startup changed before pod has synced",
			"pod", klog.KObj(pod),
			"containerID", containerID.String())
		return
	}

	// Find the container to update.
	containerStatus, _, ok := findContainerStatus(&oldStatus.status, containerID.String())
	if !ok {
		klog.InfoS("Container startup changed for unknown container",
			"pod", klog.KObj(pod),
			"containerID", containerID.String())
		return
	}

	if containerStatus.Started != nil && *containerStatus.Started == started {
		klog.V(4).InfoS("Container startup unchanged",
			"pod", klog.KObj(pod),
			"containerID", containerID.String())
		return
	}

	// Make sure we're not updating the cached version.
	status := *oldStatus.status.DeepCopy()
	containerStatus, _, _ = findContainerStatus(&status, containerID.String())
	containerStatus.Started = &started

	m.updateStatusInternal(pod, status, false) // ✅
}

// deletePodStatus simply removes the given pod from the status cache.
func (m *manager) deletePodStatus(uid types.UID) {
	m.podStatusesLock.Lock()
	defer m.podStatusesLock.Unlock()
	delete(m.podStatuses, uid)
	m.podStartupLatencyHelper.DeletePodStartupState(uid)
}

// ✅

func (m *manager) GetPodStatus(uid types.UID) (v1.PodStatus, bool) {
	m.podStatusesLock.RLock()
	defer m.podStatusesLock.RUnlock()
	status, ok := m.podStatuses[types.UID(m.podManager.TranslatePodUID(uid))]
	return status.status, ok
}

// ✅

func (m *manager) Start() { // ✅
	// Don't start the status manager if we don't have a client. This will happen
	// on the master, where the kubelet is responsible for bootstrapping the pods
	// of the master components.
	if m.kubeClient == nil {
		klog.InfoS("Kubernetes client is nil, not starting status manager")
		return
	}

	klog.InfoS("Starting to sync pod status with apiserver")

	//nolint:staticcheck // SA1015 Ticker can leak since this is only called once and doesn't handle termination.
	syncTicker := time.NewTicker(syncPeriod).C

	// syncPod and syncBatch share the same go routine to avoid sync races.
	go wait.Forever(func() {
		for {
			select {
			case syncRequest := <-m.podStatusChannel:
				klog.V(5).InfoS("Status Manager: syncing pod with status from podStatusChannel",
					"podUID", syncRequest.podUID,
					"statusVersion", syncRequest.status.version,
					"status", syncRequest.status.status)
				m.syncPod(syncRequest.podUID, syncRequest.status)
			case <-syncTicker:
				klog.V(5).InfoS("Status Manager: syncing batch")
				// remove any entries in the status channel since the batch will handle them
				for i := len(m.podStatusChannel); i > 0; i-- {
					<-m.podStatusChannel
				}
				m.syncBatch()
			}
		}
	}, 0)
}

// merges oldPodStatus and newPodStatus to preserve where pod conditions
// not owned by kubelet and to ensure terminal phase transition only happens after all
// running containers have terminated. This method does not modify the old status.
// 合并oldPodStatus和newPodStatus 以保留不属于kubelet的pod 条件，并确保终端阶段转换仅在所有正在运行的容器终止后发生。此方法不修改旧状态。
func mergePodStatus(oldPodStatus, newPodStatus v1.PodStatus, couldHaveRunningContainers bool) v1.PodStatus { // ✅
	podConditions := make([]v1.PodCondition, 0, len(oldPodStatus.Conditions)+len(newPodStatus.Conditions))

	for _, c := range oldPodStatus.Conditions {
		if !kubetypes.PodConditionByKubelet(c.Type) {
			podConditions = append(podConditions, c)
		}
	}
	// 正在向终止过度
	transitioningToTerminalPhase := !podutil.IsPodPhaseTerminal(oldPodStatus.Phase) && podutil.IsPodPhaseTerminal(newPodStatus.Phase)

	for _, c := range newPodStatus.Conditions {
		if kubetypes.PodConditionByKubelet(c.Type) {
			podConditions = append(podConditions, c)
		} else if kubetypes.PodConditionSharedByKubelet(c.Type) {
			// we replace or append all the "shared by kubelet" conditions
			if c.Type == v1.DisruptionTarget {
				// guard the update of the DisruptionTarget condition with a check to ensure
				// it will only be sent once all containers have terminated and the phase
				// is terminal. This avoids sending an unnecessary patch request to add
				// the condition if the actual status phase transition is delayed.
				if transitioningToTerminalPhase && !couldHaveRunningContainers {
					// update the LastTransitionTime again here because the older transition
					// time set in updateStatusInternal is likely stale as sending of
					// the condition was delayed until all pod's containers have terminated.
					updateLastTransitionTime(&newPodStatus, &oldPodStatus, c.Type)
					if _, c := podutil.GetPodConditionFromList(newPodStatus.Conditions, c.Type); c != nil {
						// for shared conditions we update or append in podConditions
						podConditions = statusutil.ReplaceOrAppendPodCondition(podConditions, c)
					}
				}
			}
		}
	}
	newPodStatus.Conditions = podConditions

	// Delay transitioning a pod to a terminal status unless the pod is actually terminal.
	// The Kubelet should never transition a pod to terminal status that could have running
	// containers and thus actively be leveraging exclusive resources. Note that resources
	// like volumes are reconciled by a subsystem in the Kubelet and will converge if a new
	// pod reuses an exclusive resource (unmount -> free -> mount), which means we do not
	// need wait for those resources to be detached by the Kubelet. In general, resources
	// the Kubelet exclusively owns must be released prior to a pod being reported terminal,
	// while resources that have participanting components above the API use the pod's
	// transition to a terminal phase (or full deletion) to release those resources.
	if transitioningToTerminalPhase {
		if couldHaveRunningContainers {
			newPodStatus.Phase = oldPodStatus.Phase
			newPodStatus.Reason = oldPodStatus.Reason
			newPodStatus.Message = oldPodStatus.Message
		}
	}

	// If the new phase is terminal, explicitly set the ready condition to false for v1.PodReady and v1.ContainersReady.
	// It may take some time for kubelet to reconcile the ready condition, so explicitly set ready conditions to false if the phase is terminal.
	// This is done to ensure kubelet does not report a status update with terminal pod phase and ready=true.
	// See https://issues.k8s.io/108594 for more details.
	if podutil.IsPodPhaseTerminal(newPodStatus.Phase) {
		if podutil.IsPodReadyConditionTrue(newPodStatus) || podutil.IsContainersReadyConditionTrue(newPodStatus) {
			containersReadyCondition := generateContainersReadyConditionForTerminalPhase(newPodStatus.Phase)
			podutil.UpdatePodCondition(&newPodStatus, &containersReadyCondition)

			podReadyCondition := generatePodReadyConditionForTerminalPhase(newPodStatus.Phase)
			podutil.UpdatePodCondition(&newPodStatus, &podReadyCondition)
		}
	}

	return newPodStatus
}

// 返回pod 状态是否已经稳定
func (m *manager) needsUpdate(uid types.UID, status versionedPodStatus) bool {
	latest, ok := m.apiStatusVersions[kubetypes.MirrorPodUID(uid)] // 如果这个id 不存在，需要更新
	if !ok || latest < status.version {
		return true
	}
	pod, ok := m.podManager.GetPodByUID(uid) // 常规镜像的uuid
	if !ok {
		return false
	}
	return m.canBeDeleted(pod, status.status) // 标记为删除、镜像pod 都不会更新
}

func (m *manager) canBeDeleted(pod *v1.Pod, status v1.PodStatus) bool {
	if pod.DeletionTimestamp == nil || kubetypes.IsMirrorPod(pod) { // 标记为删除、镜像pod 都不会更新
		return false
	}
	return m.podDeletionSafety.PodResourcesAreReclaimed(pod, status)
}
