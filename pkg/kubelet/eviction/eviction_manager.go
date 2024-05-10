/*
Copyright 2016 The Kubernetes Authors.

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

package eviction

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"k8s.io/klog/v2"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/tools/record"
	v1helper "k8s.io/component-helpers/scheduling/corev1"
	statsapi "k8s.io/kubelet/pkg/apis/stats/v1alpha1"
	podutil "k8s.io/kubernetes/pkg/api/v1/pod"
	apiv1resource "k8s.io/kubernetes/pkg/api/v1/resource"
	v1qos "k8s.io/kubernetes/pkg/apis/core/v1/helper/qos"
	"k8s.io/kubernetes/pkg/features"
	evictionapi "k8s.io/kubernetes/pkg/kubelet/eviction/api"
	"k8s.io/kubernetes/pkg/kubelet/lifecycle"
	"k8s.io/kubernetes/pkg/kubelet/metrics"
	"k8s.io/kubernetes/pkg/kubelet/server/stats"
	kubelettypes "k8s.io/kubernetes/pkg/kubelet/types"
	"k8s.io/utils/clock"
)

const (
	podCleanupTimeout  = 30 * time.Second
	podCleanupPollFreq = time.Second
)

const (
	signalEphemeralContainerFsLimit string = "ephemeralcontainerfs.limit" // 指在容器运行期间创建的存储,用于临时存储容器中的数据.针对单个容器
	signalEphemeralPodFsLimit       string = "ephemeralpodfs.limit"       // 针对整个 Pod
	signalEmptyDirFsLimit           string = "emptydirfs.limit"
)

// ManagerImpl implements Manager
type ManagerImpl struct {
	clock                         clock.WithTicker
	config                        Config
	killPodFunc                   KillPodFunc                             // killpod的方法
	mirrorPodFunc                 MirrorPodFunc                           // 获取静态pod的mirror pod 方法
	imageGC                       ImageGC                                 // 当node出现diskPressure condition时,imageGC进行unused images删除操作以回收disk space.
	containerGC                   ContainerGC                             //
	sync.RWMutex                                                          //
	nodeConditions                []v1.NodeConditionType                  //  当前节点存在的问题集合
	nodeConditionsLastObservedAt  nodeConditionsObservedAt                // 记录 nodecontions 上一次观察的时间
	nodeRef                       *v1.ObjectReference                     // nodeRef is a reference to the node
	recorder                      record.EventRecorder                    //
	summaryProvider               stats.SummaryProvider                   // 提供node和node上所有pods的最新status数据汇总,即 NodeStats and []PodStats.
	thresholdsFirstObservedAt     thresholdsObservedAt                    // 记录第一次阈值的时间
	thresholdsMet                 []evictionapi.Threshold                 // 保存已经触发但还没解决的Thresholds,包括那些处于grace period等待阶段的Thresholds.
	signalToRankFunc              map[evictionapi.Signal]rankFunc         // 定义各Resource进行evict挑选时的排名方法.
	signalToNodeReclaimFuncs      map[evictionapi.Signal]nodeReclaimFuncs // 定义各Resource进行回收时调用的方法
	lastObservations              signalObservations                      //
	dedicatedImageFs              *bool                                   // 指示imagefs是否位于与rootfs不同的设备上
	thresholdNotifiers            []ThresholdNotifier                     // 内存阈值通知器集合
	thresholdsLastUpdated         time.Time                               // 上次thresholdNotifiers发通知的时间
	localStorageCapacityIsolation bool                                    // 是否支持本地存储容量隔离,默认为true
}

// ensure it implements the required interface
var _ Manager = &ManagerImpl{}

// NewManager returns a configured Manager and an associated admission handler to enforce eviction configuration.
func NewManager(
	summaryProvider stats.SummaryProvider,
	config Config,
	killPodFunc KillPodFunc,
	mirrorPodFunc MirrorPodFunc,
	imageGC ImageGC,
	containerGC ContainerGC,
	recorder record.EventRecorder,
	nodeRef *v1.ObjectReference,
	clock clock.WithTicker,
	localStorageCapacityIsolation bool,
) (Manager, lifecycle.PodAdmitHandler) {
	manager := &ManagerImpl{
		clock:                         clock,
		killPodFunc:                   killPodFunc, // ✅
		mirrorPodFunc:                 mirrorPodFunc,
		imageGC:                       imageGC,
		containerGC:                   containerGC,
		config:                        config,
		recorder:                      recorder,
		summaryProvider:               summaryProvider,
		nodeRef:                       nodeRef,
		nodeConditionsLastObservedAt:  nodeConditionsObservedAt{},
		thresholdsFirstObservedAt:     thresholdsObservedAt{},
		dedicatedImageFs:              nil,
		thresholdNotifiers:            []ThresholdNotifier{},
		localStorageCapacityIsolation: localStorageCapacityIsolation, // ✅
	}
	return manager, manager // ; 用于创建pod时的admit
}

// Start 启动控制循环以观察和响应计算资源不足的情况.
func (m *ManagerImpl) Start(diskInfoProvider DiskInfoProvider, podFunc ActivePodsFunc, podCleanedUpFunc PodCleanedUpFunc, monitoringInterval time.Duration) {
	thresholdHandler := func(message string) {
		klog.InfoS(message)
		m.synchronize(diskInfoProvider, podFunc)
	}
	if m.config.KernelMemcgNotification { // 如果为true,将与内核memcg通知集成,以确定是否超过内存阈值.
		for _, threshold := range m.config.Thresholds {
			if threshold.Signal == evictionapi.SignalMemoryAvailable || threshold.Signal == evictionapi.SignalAllocatableMemoryAvailable {
				notifier, err := NewMemoryThresholdNotifier(threshold, m.config.PodCgroupRoot, &CgroupNotifierFactory{}, thresholdHandler)
				if err != nil {
					klog.InfoS("Eviction manager: failed to create memory threshold notifier", "err", err)
				} else {
					go notifier.Start()
					m.thresholdNotifiers = append(m.thresholdNotifiers, notifier)
				}
			}
		}
	}
	// 开始驱逐管理器的监控.
	go func() {
		for {
			if evictedPods := m.synchronize(diskInfoProvider, podFunc); evictedPods != nil {
				klog.InfoS("Eviction manager: pods evicted, waiting for pod to be cleaned up", "pods", klog.KObjSlice(evictedPods))
				m.waitForPodsCleanup(podCleanedUpFunc, evictedPods)
			} else {
				time.Sleep(monitoringInterval)
			}
		}
	}()
}

// IsUnderMemoryPressure returns true if the node is under memory pressure.
func (m *ManagerImpl) IsUnderMemoryPressure() bool {
	m.RLock()
	defer m.RUnlock()
	return hasNodeCondition(m.nodeConditions, v1.NodeMemoryPressure)
}

// IsUnderDiskPressure returns true if the node is under disk pressure.
func (m *ManagerImpl) IsUnderDiskPressure() bool {
	m.RLock()
	defer m.RUnlock()
	return hasNodeCondition(m.nodeConditions, v1.NodeDiskPressure)
}

// IsUnderPIDPressure returns true if the node is under PID pressure.
func (m *ManagerImpl) IsUnderPIDPressure() bool {
	m.RLock()
	defer m.RUnlock()
	return hasNodeCondition(m.nodeConditions, v1.NodePIDPressure)
}

// synchronize 是执行驱逐阈值的主要控制循环.
// 返回被杀死的pod,如果没有被杀死,则返回nil.
func (m *ManagerImpl) synchronize(diskInfoProvider DiskInfoProvider, podFunc ActivePodsFunc) []*v1.Pod {
	ctx := context.Background()
	// 如果我们没事做,就回去吧
	thresholds := m.config.Thresholds
	if len(thresholds) == 0 && !m.localStorageCapacityIsolation {
		return nil // 不会进来
	}

	klog.V(3).InfoS("Eviction Manager 正在同步 Pod 的 housekeeping（即清理、维护）操作")
	if m.dedicatedImageFs == nil { // 指示imagefs是否位于与rootfs不同的设备上  /
		// 如果imagefs与rootfs在不同的设备上,则返回true. 是否有专用的 image fs
		// /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs
		// /var/lib/kubelet
		hasImageFs, ok := diskInfoProvider.HasDedicatedImageFs(ctx) // ✅
		if ok != nil {
			return nil
		}
		m.dedicatedImageFs = &hasImageFs // 指示imagefs是否位于与rootfs不同的设备上
		// 注册各个eviction signal所对应的资源排序方法    // 将资源->排名函数.
		m.signalToRankFunc = buildSignalToRankFunc(hasImageFs)
		// 将资源->如何回收该资源的有序函数列表.
		m.signalToNodeReclaimFuncs = buildSignalToNodeReclaimFuncs(m.imageGC, m.containerGC, hasImageFs)
	}

	activePods := podFunc() // 获取pods
	updateStats := true
	summary, err := m.summaryProvider.Get(ctx, updateStats) // 获取node的状态summary
	if err != nil {
		klog.ErrorS(err, "Eviction manager: failed to get summary stats")
		return nil
	}

	if m.clock.Since(m.thresholdsLastUpdated) > notifierRefreshInterval {
		m.thresholdsLastUpdated = m.clock.Now()
		for _, notifier := range m.thresholdNotifiers { // 需要开启 KernelMemcgNotification
			if err := notifier.UpdateThreshold(summary); err != nil {
				klog.InfoS("Eviction manager: failed to update notifier", "notifier", notifier.Description(), "err", err)
			}
		}
	}
	observations, statsFunc := makeSignalObservations(summary)
	debugLogObservations("observations", observations)

	// determine the set of thresholds met independent of grace period
	// 计算得出当前触发阈值的threshold集合
	thresholds = thresholdsMet(thresholds, observations, false)
	debugLogThresholdsWithObservation("thresholds - ignoring grace period", thresholds, observations)

	// determine the set of thresholds previously met that have not yet satisfied the associated min-reclaim
	// merge之前的已经触发的但还没恢复的thresholds
	if len(m.thresholdsMet) > 0 {
		thresholdsNotYetResolved := thresholdsMet(m.thresholdsMet, observations, true)
		thresholds = mergeThresholds(thresholds, thresholdsNotYetResolved)
	}
	debugLogThresholdsWithObservation("thresholds - reclaim not satisfied", thresholds, observations)

	// track when a threshold was first observed
	now := m.clock.Now()
	thresholdsFirstObservedAt := thresholdsFirstObservedAt(thresholds, m.thresholdsFirstObservedAt, now)

	// the set of node conditions that are triggered by currently observed thresholds
	//转换得到nodeConditions
	nodeConditions := nodeConditions(thresholds)
	if len(nodeConditions) > 0 {
		klog.V(3).InfoS("Eviction manager: node conditions - observed", "nodeCondition", nodeConditions)
	}

	// 跟踪节点状态最后观察到的时间
	nodeConditionsLastObservedAt := nodeConditionsLastObservedAt(nodeConditions, m.nodeConditionsLastObservedAt, now)

	// node conditions report true if it has been observed within the transition period window
	nodeConditions = nodeConditionsObservedSince(nodeConditionsLastObservedAt, m.config.PressureTransitionPeriod, now)
	if len(nodeConditions) > 0 {
		klog.V(3).InfoS("Eviction manager: node conditions - transition period not met", "nodeCondition", nodeConditions)
	}

	// determine the set of thresholds we need to drive eviction behavior (i.e. all grace periods are met)
	//过滤出满足优雅删除的thresholds
	thresholds = thresholdsMetGracePeriod(thresholdsFirstObservedAt, now)
	debugLogThresholdsWithObservation("thresholds - grace periods satisfied", thresholds, observations)

	// 更新内部状态
	m.Lock()
	m.nodeConditions = nodeConditions
	m.thresholdsFirstObservedAt = thresholdsFirstObservedAt
	m.nodeConditionsLastObservedAt = nodeConditionsLastObservedAt
	m.thresholdsMet = thresholds

	// determine the set of thresholds whose stats have been updated since the last sync
	//从这轮的观察结果中去掉上一轮的观察结果出现的thresholds
	thresholds = thresholdsUpdatedStats(thresholds, observations, m.lastObservations)
	debugLogThresholdsWithObservation("thresholds - updated stats", thresholds, observations)

	m.lastObservations = observations
	m.Unlock()
	// 如果本地卷临时存储存在资源使用冲突,则清除pod
	// 如果在localStorageEviction函数中发生了 evection,则跳过其余的 evection 动作
	if m.localStorageCapacityIsolation {
		if evictedPods := m.localStorageEviction(activePods, statsFunc); len(evictedPods) > 0 {
			return evictedPods
		}
	}

	if len(thresholds) == 0 {
		klog.V(3).InfoS("Eviction manager: no resources are starved")
		return nil
	}

	// rank the thresholds by eviction priority
	//按照驱逐的优先级给thresholds排序
	sort.Sort(byEvictionPriority(thresholds))
	thresholdToReclaim, resourceToReclaim, foundAny := getReclaimableThreshold(thresholds)
	if !foundAny {
		return nil
	}
	klog.InfoS("Eviction manager: attempting to reclaim", "resourceName", resourceToReclaim)

	// record an event about the resources we are now attempting to reclaim via eviction
	m.recorder.Eventf(m.nodeRef, v1.EventTypeWarning, "EvictionThresholdMet", "Attempting to reclaim %s", resourceToReclaim)

	// check if there are node-level resources we can reclaim to reduce pressure before evicting end-user pods.
	//按照优先级最高的threshold回收节点资源,意思是先判断能否回收节点资源
	if m.reclaimNodeLevelResources(ctx, thresholdToReclaim.Signal, resourceToReclaim) {
		klog.InfoS("Eviction manager: able to reduce resource pressure without evicting pods.", "resourceName", resourceToReclaim)
		return nil
	}

	klog.InfoS("Eviction manager: must evict pod(s) to reclaim", "resourceName", resourceToReclaim)

	// rank the pods for eviction
	//使用rank方法排序
	rank, ok := m.signalToRankFunc[thresholdToReclaim.Signal]
	if !ok {
		klog.ErrorS(nil, "Eviction manager: no ranking function for signal", "threshold", thresholdToReclaim.Signal)
		return nil
	}

	// the only candidates viable for eviction are those pods that had anything running.
	if len(activePods) == 0 {
		klog.ErrorS(nil, "Eviction manager: eviction thresholds have been met, but no pods are active to evict")
		return nil
	}

	// rank the running pods for eviction for the specified resource
	rank(activePods, statsFunc)

	klog.InfoS("Eviction manager: pods ranked for eviction", "pods", klog.KObjSlice(activePods))

	//record age of metrics for met thresholds that we are using for evictions.
	for _, t := range thresholds {
		timeObserved := observations[t.Signal].time
		if !timeObserved.IsZero() {
			metrics.EvictionStatsAge.WithLabelValues(string(t.Signal)).Observe(metrics.SinceInSeconds(timeObserved.Time))
		}
	}

	// 执行驱逐动作,我们在每次驱逐间隔中最多杀死一个pod
	for i := range activePods {
		pod := activePods[i]
		gracePeriodOverride := int64(0)
		if !isHardEvictionThreshold(thresholdToReclaim) {
			gracePeriodOverride = m.config.MaxPodGracePeriodSeconds
		}
		message, annotations := evictionMessage(resourceToReclaim, pod, statsFunc, thresholds, observations)
		var condition *v1.PodCondition
		if utilfeature.DefaultFeatureGate.Enabled(features.PodDisruptionConditions) {
			condition = &v1.PodCondition{
				Type:    v1.DisruptionTarget,
				Status:  v1.ConditionTrue,
				Reason:  v1.PodReasonTerminationByKubelet,
				Message: message,
			}
		}
		if m.evictPod(pod, gracePeriodOverride, message, annotations, condition) {
			metrics.Evictions.WithLabelValues(string(thresholdToReclaim.Signal)).Inc()
			return []*v1.Pod{pod}
		}
	}
	klog.InfoS("Eviction manager: unable to evict any pods from the node")
	return nil
}

func (m *ManagerImpl) waitForPodsCleanup(podCleanedUpFunc PodCleanedUpFunc, pods []*v1.Pod) {
	timeout := m.clock.NewTimer(podCleanupTimeout)
	defer timeout.Stop()
	ticker := m.clock.NewTicker(podCleanupPollFreq)
	defer ticker.Stop()
	for {
		select {
		case <-timeout.C():
			klog.InfoS("Eviction manager: timed out waiting for pods to be cleaned up", "pods", klog.KObjSlice(pods))
			return
		case <-ticker.C():
			for i, pod := range pods {
				if !podCleanedUpFunc(pod) {
					break
				}
				if i == len(pods)-1 {
					klog.InfoS("Eviction manager: pods successfully cleaned up", "pods", klog.KObjSlice(pods))
					return
				}
			}
		}
	}
}

// reclaimNodeLevelResources attempts to reclaim node level resources.  returns true if thresholds were satisfied and no pod eviction is required.
func (m *ManagerImpl) reclaimNodeLevelResources(ctx context.Context, signalToReclaim evictionapi.Signal, resourceToReclaim v1.ResourceName) bool {
	nodeReclaimFuncs := m.signalToNodeReclaimFuncs[signalToReclaim]
	for _, nodeReclaimFunc := range nodeReclaimFuncs {
		// attempt to reclaim the pressured resource.
		if err := nodeReclaimFunc(ctx); err != nil {
			klog.InfoS("Eviction manager: unexpected error when attempting to reduce resource pressure", "resourceName", resourceToReclaim, "err", err)
		}

	}
	if len(nodeReclaimFuncs) > 0 {
		summary, err := m.summaryProvider.Get(ctx, true)
		if err != nil {
			klog.ErrorS(err, "Eviction manager: failed to get summary stats after resource reclaim")
			return false
		}

		// make observations and get a function to derive pod usage stats relative to those observations.
		observations, _ := makeSignalObservations(summary)
		debugLogObservations("observations after resource reclaim", observations)

		// evaluate all thresholds independently of their grace period to see if with
		// the new observations, we think we have met min reclaim goals
		thresholds := thresholdsMet(m.config.Thresholds, observations, true)
		debugLogThresholdsWithObservation("thresholds after resource reclaim - ignoring grace period", thresholds, observations)

		if len(thresholds) == 0 {
			return true
		}
	}
	return false
}

// localStorageEviction checks the EmptyDir volume usage for each pod and determine whether it exceeds the specified limit and needs
// to be evicted. It also checks every container in the pod, if the container overlay usage exceeds the limit, the pod will be evicted too.
func (m *ManagerImpl) localStorageEviction(pods []*v1.Pod, statsFunc statsFunc) []*v1.Pod {
	evicted := []*v1.Pod{}
	for _, pod := range pods {
		podStats, ok := statsFunc(pod)
		if !ok {
			continue
		}

		if m.emptyDirLimitEviction(podStats, pod) {
			evicted = append(evicted, pod)
			continue
		}

		if m.podEphemeralStorageLimitEviction(podStats, pod) {
			evicted = append(evicted, pod)
			continue
		}

		if m.containerEphemeralStorageLimitEviction(podStats, pod) {
			evicted = append(evicted, pod)
		}
	}

	return evicted
}

func (m *ManagerImpl) emptyDirLimitEviction(podStats statsapi.PodStats, pod *v1.Pod) bool {
	podVolumeUsed := make(map[string]*resource.Quantity)
	for _, volume := range podStats.VolumeStats {
		podVolumeUsed[volume.Name] = resource.NewQuantity(int64(*volume.UsedBytes), resource.BinarySI)
	}
	for i := range pod.Spec.Volumes {
		source := &pod.Spec.Volumes[i].VolumeSource
		if source.EmptyDir != nil {
			size := source.EmptyDir.SizeLimit
			used := podVolumeUsed[pod.Spec.Volumes[i].Name]
			if used != nil && size != nil && size.Sign() == 1 && used.Cmp(*size) > 0 {
				// the emptyDir usage exceeds the size limit, evict the pod
				if m.evictPod(pod, 0, fmt.Sprintf(emptyDirMessageFmt, pod.Spec.Volumes[i].Name, size.String()), nil, nil) {
					metrics.Evictions.WithLabelValues(signalEmptyDirFsLimit).Inc()
					return true
				}
				return false
			}
		}
	}

	return false
}

func (m *ManagerImpl) podEphemeralStorageLimitEviction(podStats statsapi.PodStats, pod *v1.Pod) bool {
	_, podLimits := apiv1resource.PodRequestsAndLimits(pod)
	_, found := podLimits[v1.ResourceEphemeralStorage]
	if !found {
		return false
	}

	// pod stats api summarizes ephemeral storage usage (container, emptyDir, host[etc-hosts, logs])
	podEphemeralStorageTotalUsage := &resource.Quantity{}
	if podStats.EphemeralStorage != nil && podStats.EphemeralStorage.UsedBytes != nil {
		podEphemeralStorageTotalUsage = resource.NewQuantity(int64(*podStats.EphemeralStorage.UsedBytes), resource.BinarySI)
	}
	podEphemeralStorageLimit := podLimits[v1.ResourceEphemeralStorage]
	if podEphemeralStorageTotalUsage.Cmp(podEphemeralStorageLimit) > 0 {
		// the total usage of pod exceeds the total size limit of containers, evict the pod
		message := fmt.Sprintf(podEphemeralStorageMessageFmt, podEphemeralStorageLimit.String())
		if m.evictPod(pod, 0, message, nil, nil) {
			metrics.Evictions.WithLabelValues(signalEphemeralPodFsLimit).Inc()
			return true
		}
		return false
	}
	return false
}

func (m *ManagerImpl) containerEphemeralStorageLimitEviction(podStats statsapi.PodStats, pod *v1.Pod) bool {
	thresholdsMap := make(map[string]*resource.Quantity)
	for _, container := range pod.Spec.Containers {
		ephemeralLimit := container.Resources.Limits.StorageEphemeral()
		if ephemeralLimit != nil && ephemeralLimit.Value() != 0 {
			thresholdsMap[container.Name] = ephemeralLimit
		}
	}

	for _, containerStat := range podStats.Containers {
		containerUsed := diskUsage(containerStat.Logs)
		if !*m.dedicatedImageFs { // 没有专用的 imagefs 存储盘
			containerUsed.Add(*diskUsage(containerStat.Rootfs))
		}

		if ephemeralStorageThreshold, ok := thresholdsMap[containerStat.Name]; ok {
			if ephemeralStorageThreshold.Cmp(*containerUsed) < 0 {
				if m.evictPod(pod, 0, fmt.Sprintf(containerEphemeralStorageMessageFmt, containerStat.Name, ephemeralStorageThreshold.String()), nil, nil) {
					metrics.Evictions.WithLabelValues(signalEphemeralContainerFsLimit).Inc()
					return true
				}
				return false
			}
		}
	}
	return false
}

// --------------------------------------------------------------------------------------------------------------------------------------------

func (m *ManagerImpl) evictPod(pod *v1.Pod, gracePeriodOverride int64, evictMsg string, annotations map[string]string, condition *v1.PodCondition) bool {
	// If the pod is marked as critical and static, and support for critical pod annotations is enabled,
	// do not evict such pods. Static pods are not re-admitted after evictions.
	// https://github.com/kubernetes/kubernetes/issues/40573 has more details.
	if kubelettypes.IsCriticalPod(pod) {
		klog.ErrorS(nil, "Eviction manager: cannot evict a critical pod", "pod", klog.KObj(pod))
		return false
	}
	// record that we are evicting the pod
	m.recorder.AnnotatedEventf(pod, annotations, v1.EventTypeWarning, Reason, evictMsg)
	// this is a blocking call and should only return when the pod and its containers are killed.
	klog.V(3).InfoS("Evicting pod", "pod", klog.KObj(pod), "podUID", pod.UID, "message", evictMsg)
	err := m.killPodFunc(pod, true, &gracePeriodOverride, func(status *v1.PodStatus) { // ✅
		status.Phase = v1.PodFailed
		status.Reason = Reason
		status.Message = evictMsg
		if condition != nil {
			podutil.UpdatePodCondition(status, condition)
		}
	})
	if err != nil {
		klog.ErrorS(err, "Eviction manager: pod failed to evict", "pod", klog.KObj(pod))
	} else {
		klog.InfoS("Eviction manager: pod is evicted successfully", "pod", klog.KObj(pod))
	}
	return true
}

// Admit 评估一个pod是否可以被允许创建.
// 用node的压力状态 做pod是否准入的依据,相当于影响调度的结果
func (m *ManagerImpl) Admit(attrs *lifecycle.PodAdmitAttributes) lifecycle.PodAdmitResult { // ✅
	m.RLock()
	defer m.RUnlock()
	if len(m.nodeConditions) == 0 { // 如果 node现在没有压力状态那么准入
		return lifecycle.PodAdmitResult{Admit: true}
	}
	// Admit Critical pods even under resource pressure since they are required for system stability.
	// https://github.com/kubernetes/kubernetes/issues/40573 has more details.
	if kubelettypes.IsCriticalPod(attrs.Pod) { // 如果是静态pod或者SystemCriticalPriority的高优则忽略节点压力状态准入
		return lifecycle.PodAdmitResult{Admit: true}
	}

	// Conditions other than memory pressure reject all pods
	// 如果当前节点只有内存的压力,那么pod的qos类型为 非 BestEffort[最低] 则准入
	nodeOnlyHasMemoryPressureCondition := hasNodeCondition(m.nodeConditions, v1.NodeMemoryPressure) && len(m.nodeConditions) == 1
	if nodeOnlyHasMemoryPressureCondition {
		notBestEffort := v1.PodQOSBestEffort != v1qos.GetPodQOS(attrs.Pod)
		if notBestEffort {
			// 不是努力送达
			return lifecycle.PodAdmitResult{Admit: true} // 低优先级的不让进、高优先级的让进
		}

		// 如果是BestEffort则要根据它的容忍类型判断

		if v1helper.TolerationsTolerateTaint(attrs.Pod.Spec.Tolerations, &v1.Taint{
			Key:    v1.TaintNodeMemoryPressure,
			Effect: v1.TaintEffectNoSchedule,
		}) {
			return lifecycle.PodAdmitResult{Admit: true} // 低优先级、但是容忍这个污点让进
		}
	}

	// reject pods when under memory pressure (if pod is best effort), or if under disk pressure.
	klog.InfoS("无法将pod分配到节点上.", "pod", klog.KObj(attrs.Pod), "nodeCondition", m.nodeConditions)
	return lifecycle.PodAdmitResult{
		Admit:   false,
		Reason:  Reason, // ✅
		Message: fmt.Sprintf(nodeConditionMessageFmt, m.nodeConditions),
	}
}
