/*
Copyright 2017 The Kubernetes Authors.

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

package preemption

import (
	"fmt"
	"math"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/api/v1/resource"
	v1qos "k8s.io/kubernetes/pkg/apis/core/v1/helper/qos"
	"k8s.io/kubernetes/pkg/kubelet/events"
	"k8s.io/kubernetes/pkg/kubelet/eviction"
	"k8s.io/kubernetes/pkg/kubelet/lifecycle"
	"k8s.io/kubernetes/pkg/kubelet/metrics"
	kubetypes "k8s.io/kubernetes/pkg/kubelet/types"
)

// 抢占

const message = "为了让关键pod进入，先发制人\n "

//在容器编排系统如Kubernetes中，Preemption通常指的是当节点资源不足时，系统可以暂停正在运行的Pod，将其资源分配给更高优先级的Pod，以确保系统的正常运行。
//Kubernetes中的Preemption通常与Pod的调度器和调度策略一起使用，以确保Pod能够在节点上得到合适的资源，同时最大化节点的利用率。
//例如，Kubernetes中可以使用Pod的Priority和QoS Class来定义Pod的优先级和资源需求，以便在资源不足时进行Preemption和重新调度。

// CriticalPodAdmissionHandler is an AdmissionFailureHandler that handles admission failure for Critical Pods.
// If the ONLY admission failures are due to insufficient resources, then CriticalPodAdmissionHandler evicts pods
// so that the critical pod can be admitted.  For evictions, the CriticalPodAdmissionHandler evicts a set of pods that
// frees up the required resource requests.  The set of pods is designed to minimize impact, and is prioritized according to the ordering:
// minimal impact for guaranteed pods > minimal impact for burstable pods > minimal impact for besteffort pods.
// minimal impact is defined as follows: fewest pods evicted > fewest total requests of pods.
// finding the fewest total requests of pods is considered besteffort.
type CriticalPodAdmissionHandler struct {
	getPodsFunc eviction.ActivePodsFunc
	killPodFunc eviction.KillPodFunc
	recorder    record.EventRecorder
}

var _ lifecycle.AdmissionFailureHandler = &CriticalPodAdmissionHandler{}

func NewCriticalPodAdmissionHandler(getPodsFunc eviction.ActivePodsFunc, killPodFunc eviction.KillPodFunc, recorder record.EventRecorder) *CriticalPodAdmissionHandler {
	return &CriticalPodAdmissionHandler{
		getPodsFunc: getPodsFunc,
		killPodFunc: killPodFunc,
		recorder:    recorder,
	}
}

func (c *CriticalPodAdmissionHandler) HandleAdmissionFailure( // ✅
	admitPod *v1.Pod,
	failureReasons []lifecycle.PredicateFailureReason,
) ([]lifecycle.PredicateFailureReason, error) {
	// pod 资源准入失败后的回调,这可能是由于多种原因导致的,例如网络故障、磁盘空间不足、权限问题等.例如释放一些资源 重试

	if !kubetypes.IsCriticalPod(admitPod) {
		return failureReasons, nil
	}
	// 重要的pod 需要处理

	// InsufficientResourceError 不能成为拒绝一个关键 pod 的理由.
	var nonResourceReasons []lifecycle.PredicateFailureReason
	var resourceReasons []*admissionRequirement
	for _, reason := range failureReasons {
		if r, ok := reason.(*lifecycle.InsufficientResourceError); ok {
			resourceReasons = append(resourceReasons, &admissionRequirement{
				resourceName: r.ResourceName,
				quantity:     r.GetInsufficientAmount(),
			})
		} else {
			nonResourceReasons = append(nonResourceReasons, reason)
		}
	}
	if len(nonResourceReasons) > 0 {
		// 只返回与资源无关的原因,因为关键pod不能因为资源原因导致准入失败.
		return nonResourceReasons, nil
	}
	err := c.evictPodsToFreeRequests(admitPod, admissionRequirementList(resourceReasons)) // ✅
	// 如果没有返回错误,则抢占成功,pod可以安全接受.
	return nil, err
}

// 驱逐pod,来释放资源
// 尝试根据请求驱逐pod来释放这些资源.例如,如果唯一不足的资源是200Mb内存,则该函数可以驱逐request=250Mb的pod.
func (c *CriticalPodAdmissionHandler) evictPodsToFreeRequests(admitPod *v1.Pod, insufficientResources admissionRequirementList) error {
	podsToPreempt, err := getPodsToPreempt(admitPod, c.getPodsFunc(), insufficientResources) // 获取能满足需求的 要释放的pod列表 ✅
	if err != nil {
		return fmt.Errorf("preemption: error finding a set of pods to preempt: %v", err)
	}
	for _, pod := range podsToPreempt {
		// record that we are evicting the pod
		c.recorder.Eventf(pod, v1.EventTypeWarning, events.PreemptContainer, message)
		// this is a blocking call and should only return when the pod and its containers are killed.
		klog.V(3).InfoS("抢占pod 来释放资源", "pod", klog.KObj(pod), "podUID", pod.UID, "insufficientResources", insufficientResources)
		err := c.killPodFunc(pod, true, nil, func(status *v1.PodStatus) { // ✅
			status.Phase = v1.PodFailed
			status.Reason = events.PreemptContainer
			status.Message = message
		})
		if err != nil {
			klog.ErrorS(err, "Failed to evict pod", "pod", klog.KObj(pod))
			// In future syncPod loops, the kubelet will retry the pod deletion steps that it was stuck on.
			continue
		}
		if len(insufficientResources) > 0 {
			metrics.Preemptions.WithLabelValues(insufficientResources[0].resourceName.String()).Inc()
		} else {
			metrics.Preemptions.WithLabelValues("").Inc()
		}
		klog.InfoS("Pod evicted successfully", "pod", klog.KObj(pod))
	}
	return nil
}

// 返回一个可以驱逐的pod 列表 free requests >= requirements
func getPodsToPreempt(pod *v1.Pod, pods []*v1.Pod, requirements admissionRequirementList) ([]*v1.Pod, error) {
	bestEffortPods, burstablePods, guaranteedPods := sortPodsByQOS(pod, pods) // ✅

	// make sure that pods exist to reclaim the requirements
	// 确保存在回收需求的pod
	unableToMeetRequirements := requirements.subtract(append(append(bestEffortPods, burstablePods...), guaranteedPods...)...) // 判断是不是驱逐了所有pod 仍然资源不够
	if len(unableToMeetRequirements) > 0 {
		// 不满足需求的资源指标
		return nil, fmt.Errorf("没有找到一组运行的pod来回收资源: %v", unableToMeetRequirements.toString())
	}

	// find the guaranteed pods we would need to evict if we already evicted ALL burstable and besteffort pods.
	guaranteedToEvict, err := getPodsToPreemptByDistance(guaranteedPods, requirements.subtract(append(bestEffortPods, burstablePods...)...)) //✅
	if err != nil {
		return nil, err
	}
	// Find the burstable pods we would need to evict if we already evicted ALL besteffort pods, and the required guaranteed pods.
	burstableToEvict, err := getPodsToPreemptByDistance(burstablePods, requirements.subtract(append(bestEffortPods, guaranteedToEvict...)...)) //✅
	if err != nil {
		return nil, err
	}
	// Find the besteffort pods we would need to evict if we already evicted the required guaranteed and burstable pods.
	bestEffortToEvict, err := getPodsToPreemptByDistance(bestEffortPods, requirements.subtract(append(burstableToEvict, guaranteedToEvict...)...)) //✅
	if err != nil {
		return nil, err
	}
	return append(append(bestEffortToEvict, burstableToEvict...), guaranteedToEvict...), nil
}

// 对pod的驱逐排序
func getPodsToPreemptByDistance(pods []*v1.Pod, requirements admissionRequirementList) ([]*v1.Pod, error) {
	podsToEvict := []*v1.Pod{}
	// 以离剩余需求最近的距离驱逐pod,每轮更新需求.
	for len(requirements) > 0 {
		if len(pods) == 0 {
			return nil, fmt.Errorf("no set of running pods found to reclaim resources: %v", requirements.toString())
		}
		// all distances must be less than len(requirements), because the max distance for a single requirement is 1
		bestDistance := float64(len(requirements) + 1)
		bestPodIndex := 0
		// Find the pod with the smallest distance from requirements
		// Or, in the case of two equidistant pods, find the pod with "smaller" resource requests.
		for i, pod := range pods {
			dist := requirements.distance(pod)
			if dist < bestDistance || (bestDistance == dist && smallerResourceRequest(pod, pods[bestPodIndex])) {
				bestDistance = dist
				bestPodIndex = i
			}
		}
		// subtract the pod from requirements, and transfer the pod from input-pods to pods-to-evicted
		requirements = requirements.subtract(pods[bestPodIndex]) // 计算还需要多少资源
		podsToEvict = append(podsToEvict, pods[bestPodIndex])
		pods[bestPodIndex] = pods[len(pods)-1]
		pods = pods[:len(pods)-1]
	}
	return podsToEvict, nil
}

// 准入所需的资源
type admissionRequirement struct {
	resourceName v1.ResourceName // 资源名称
	quantity     int64           // 仍然需要的资源额度
}

type admissionRequirementList []*admissionRequirement // 资源不足的列表

func (a admissionRequirementList) distance(pod *v1.Pod) float64 { // 整体资源的 需求满足度
	dist := float64(0) // 需求满足度
	for _, req := range a {
		remainingRequest := float64(req.quantity - resource.GetResourceRequest(pod, req.resourceName))
		if remainingRequest > 0 {
			dist += math.Pow(remainingRequest/float64(req.quantity), 2)
		}
	}
	return dist
}

// 排除pods的资源后,还需要多少资源
func (a admissionRequirementList) subtract(pods ...*v1.Pod) admissionRequirementList {
	// 判断是不是驱逐了所有pod 仍然资源不够
	newList := []*admissionRequirement{}
	for _, req := range a { // 资源不足的列表 (还需要多少)
		newQuantity := req.quantity
		for _, pod := range pods { // 可以被抢占的pod
			newQuantity -= resource.GetResourceRequest(pod, req.resourceName)
			if newQuantity <= 0 {
				break
			}
		}
		if newQuantity > 0 {
			newList = append(newList, &admissionRequirement{
				resourceName: req.resourceName,
				quantity:     newQuantity,
			})
		}
	}
	return newList
}

func (a admissionRequirementList) toString() string {
	s := "["
	for _, req := range a {
		s += fmt.Sprintf("(res: %v, q: %d), ", req.resourceName, req.quantity)
	}
	return s + "]"
}

// 返回可以被抢占的 三种pod 列表
func sortPodsByQOS(preemptor *v1.Pod, pods []*v1.Pod) (bestEffort, burstable, guaranteed []*v1.Pod) {
	for _, pod := range pods {
		if kubetypes.Preemptable(preemptor, pod) { // 比较pod重要性 ,优先级
			switch v1qos.GetPodQOS(pod) {
			case v1.PodQOSBestEffort:
				bestEffort = append(bestEffort, pod)
			case v1.PodQOSBurstable:
				burstable = append(burstable, pod)
			case v1.PodQOSGuaranteed:
				guaranteed = append(guaranteed, pod)
			default:
			}
		}
	}

	return
}

// smallerResourceRequest returns true if pod1 has a smaller request than pod2
func smallerResourceRequest(pod1 *v1.Pod, pod2 *v1.Pod) bool {
	priorityList := []v1.ResourceName{
		v1.ResourceMemory,
		v1.ResourceCPU,
	}
	for _, res := range priorityList {
		req1 := resource.GetResourceRequest(pod1, res)
		req2 := resource.GetResourceRequest(pod2, res)
		if req1 < req2 {
			return true
		} else if req1 > req2 {
			return false
		}
	}
	return true
}
