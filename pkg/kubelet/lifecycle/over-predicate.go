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

package lifecycle

import (
	"fmt"
	"runtime"

	v1 "k8s.io/api/core/v1"
	"k8s.io/component-helpers/scheduling/corev1"
	"k8s.io/klog/v2"
	v1helper "k8s.io/kubernetes/pkg/apis/core/v1/helper"
	"k8s.io/kubernetes/pkg/kubelet/types"
	"k8s.io/kubernetes/pkg/over_scheduler"
	schedulerframework "k8s.io/kubernetes/pkg/over_scheduler/framework"
	"k8s.io/kubernetes/pkg/over_scheduler/framework/plugins/tainttoleration"
)

type getNodeAnyWayFuncType func() (*v1.Node, error)

type pluginResourceUpdateFuncType func(*schedulerframework.NodeInfo, *PodAdmitAttributes) error

// AdmissionFailureHandler is an interface which defines how to deal with a failure to admit a pod.
// This allows for the graceful handling of pod admission failure.
type AdmissionFailureHandler interface {
	HandleAdmissionFailure(admitPod *v1.Pod, failureReasons []PredicateFailureReason) ([]PredicateFailureReason, error)
}

type predicateAdmitHandler struct {
	getNodeAnyWayFunc        getNodeAnyWayFuncType
	pluginResourceUpdateFunc pluginResourceUpdateFuncType
	admissionFailureHandler  AdmissionFailureHandler
}

var _ PodAdmitHandler = &predicateAdmitHandler{}

func NewPredicateAdmitHandler(
	getNodeAnyWayFunc getNodeAnyWayFuncType,
	admissionFailureHandler AdmissionFailureHandler,
	pluginResourceUpdateFunc pluginResourceUpdateFuncType,
) PodAdmitHandler {
	return &predicateAdmitHandler{
		getNodeAnyWayFunc,
		pluginResourceUpdateFunc,
		admissionFailureHandler,
	}
}

func (w *predicateAdmitHandler) Admit(attrs *PodAdmitAttributes) PodAdmitResult { // ✅

	//Pod       *v1.Pod   // 要评估准入的 Pod.
	//OtherPods []*v1.Pod // 所有绑定到 kubelet 的 Pod,不包括正在评估的 Pod.

	node, err := w.getNodeAnyWayFunc()
	if err != nil {
		klog.ErrorS(err, "Cannot get Node info")
		return PodAdmitResult{
			Admit:   false,
			Reason:  "InvalidNodeInfo",
			Message: "Kubelet cannot get node info.",
		}
	}
	admitPod := attrs.Pod
	pods := attrs.OtherPods
	nodeInfo := schedulerframework.NewNodeInfo(pods...)
	nodeInfo.SetNode(node)
	// 确保节点有足够的资源来满足pod的需求
	if err = w.pluginResourceUpdateFunc(nodeInfo, attrs); err != nil { // 更新deviceManager上的资源信息
		message := fmt.Sprintf("Update plugin resources failed due to %v, which is unexpected.", err)
		klog.InfoS("Failed to admit pod", "pod", klog.KObj(admitPod), "message", message)
		return PodAdmitResult{
			Admit:   false,
			Reason:  "UnexpectedAdmissionError",
			Message: message,
		}
	}

	// 删除节点信息中缺少的扩展资源请求.这是支持集群级资源所必需的,这些资源是节点未知的扩展资源.
	podWithoutMissingExtendedResources := removeMissingExtendedResources(admitPod, nodeInfo)

	reasons := generalFilter(podWithoutMissingExtendedResources, nodeInfo) // 资源、污点 的检查
	fit := len(reasons) == 0
	if !fit {
		// 尝试判断 准入失败 是不是误判
		reasons, err = w.admissionFailureHandler.HandleAdmissionFailure(admitPod, reasons) // ✅
		fit = len(reasons) == 0 && err == nil
		if err != nil {
			message := fmt.Sprintf("Unexpected error while attempting to recover from admission failure: %v", err)
			klog.InfoS("尝试从拒绝 Pod 的错误中恢复时出现了意外错误.", "pod", klog.KObj(admitPod), "err", err)
			return PodAdmitResult{
				Admit:   fit,
				Reason:  "UnexpectedAdmissionError",
				Message: message,
			}
		}
	}
	if !fit {
		// 仍然有不满足需求的资源
		var reason string
		var message string
		if len(reasons) == 0 {
			message = fmt.Sprint("由于未知原因导致GeneralPredicates失败,这是意外的.")
			klog.InfoS("未能承认pod:由于未知原因导致GeneralPredicates失败,这是意外的", "pod", klog.KObj(admitPod))
			return PodAdmitResult{
				Admit:   fit,
				Reason:  "UnknownReason",
				Message: message,
			}
		}
		// If there are failed predicates, we only return the first one as a reason.
		r := reasons[0]
		switch re := r.(type) {
		case *PredicateFailureError:
			reason = re.PredicateName
			message = re.Error()
			klog.V(2).InfoS("Predicate failed on Pod", "pod", klog.KObj(admitPod), "err", message)
		case *InsufficientResourceError:
			reason = fmt.Sprintf("OutOf%s", re.ResourceName)
			message = re.Error()
			klog.V(2).InfoS("Predicate failed on Pod", "pod", klog.KObj(admitPod), "err", message)
		default:
			reason = "UnexpectedPredicateFailureType"
			message = fmt.Sprintf("GeneralPredicates failed due to %v, which is unexpected.", r)
			klog.InfoS("Failed to admit pod", "pod", klog.KObj(admitPod), "err", message)
		}
		return PodAdmitResult{
			Admit:   fit,
			Reason:  reason,
			Message: message,
		}
	}

	// 资源满足

	if rejectPodAdmissionBasedOnOSSelector(admitPod, node) { // 判断 os 是否符合
		return PodAdmitResult{
			Admit:   false,
			Reason:  "PodOSSelectorNodeLabelDoesNotMatch",
			Message: "Failed to admit pod as the `kubernetes.io/os` label doesn't match node label",
		}
	}
	if rejectPodAdmissionBasedOnOSField(admitPod) {
		return PodAdmitResult{
			Admit:   false,
			Reason:  "PodOSNotSupported",
			Message: "评估pod失败,因为OS字段与节点OS不匹配",
		}
	}
	return PodAdmitResult{
		Admit: true,
	}
}

// rejectPodAdmissionBasedOnOSSelector rejects pod if it's nodeSelector doesn't match
// We expect the kubelet status reconcile which happens every 10sec to update the node labels if there is a mismatch.
func rejectPodAdmissionBasedOnOSSelector(pod *v1.Pod, node *v1.Node) bool {
	labels := node.Labels
	osName, osLabelExists := labels[v1.LabelOSStable]
	if !osLabelExists || osName != runtime.GOOS {
		if len(labels) == 0 {
			labels = make(map[string]string)
		}
		labels[v1.LabelOSStable] = runtime.GOOS
	}
	podLabelSelector, podOSLabelExists := pod.Labels[v1.LabelOSStable]
	if !podOSLabelExists {
		// If the labelselector didn't exist, let's keep the current behavior as is
		return false
	} else if podOSLabelExists && podLabelSelector != labels[v1.LabelOSStable] {
		return true
	}
	return false
} // ✅

// rejectPodAdmissionBasedOnOSField rejects pods if their OS field doesn't match runtime.GOOS.
// TODO: Relax this restriction when we start supporting LCOW in kubernetes where podOS may not match
//
//	node's OS.
func rejectPodAdmissionBasedOnOSField(pod *v1.Pod) bool {
	if pod.Spec.OS == nil {
		return false
	}
	// If the pod OS doesn't match runtime.GOOS return false
	return string(pod.Spec.OS.Name) != runtime.GOOS
}

// 删除pod 扩展zi'yuau
func removeMissingExtendedResources(pod *v1.Pod, nodeInfo *schedulerframework.NodeInfo) *v1.Pod {
	podCopy := pod.DeepCopy()
	for i, c := range pod.Spec.Containers {
		// We only handle requests in Requests but not Limits because the
		// PodFitsResources predicate, to which the result pod will be passed,
		// does not use Limits.
		podCopy.Spec.Containers[i].Resources.Requests = make(v1.ResourceMap) // 清空
		for rName, rQuant := range c.Resources.Requests {
			if v1helper.IsExtendedResourceName(rName) {
				if _, found := nodeInfo.Allocatable.ScalarResources[rName]; !found {
					continue
				}
			}
			podCopy.Spec.Containers[i].Resources.Requests[rName] = rQuant
		}
	}
	return podCopy
}

// InsufficientResourceError 因为资源不足导致的 admit 失败
type InsufficientResourceError struct {
	ResourceName v1.ResourceName // 资源名称
	Requested    int64
	Used         int64
	Capacity     int64
}

var _ PredicateFailureReason = &InsufficientResourceError{}

func (e *InsufficientResourceError) Error() string {
	return fmt.Sprintf("Node didn't have enough resource: %s, requested: %d, used: %d, capacity: %d",
		e.ResourceName, e.Requested, e.Used, e.Capacity)
}

type PredicateFailureReason interface {
	GetReason() string
}

// GetReason returns the reason of the InsufficientResourceError.
func (e *InsufficientResourceError) GetReason() string {
	return fmt.Sprintf("Insufficient %v", e.ResourceName)
}

// GetInsufficientAmount 返回错误中资源不足的数量.
func (e *InsufficientResourceError) GetInsufficientAmount() int64 {
	return e.Requested - (e.Capacity - e.Used)
}

// PredicateFailureError describes a failure error of predicate.
type PredicateFailureError struct {
	PredicateName string
	PredicateDesc string
}

func (e *PredicateFailureError) Error() string {
	return fmt.Sprintf("Predicate %s failed", e.PredicateName)
}

// GetReason returns the reason of the PredicateFailureError.
func (e *PredicateFailureError) GetReason() string {
	return e.PredicateDesc
}

// 检查kubelet关心的一组过滤器.
func generalFilter(pod *v1.Pod, nodeInfo *schedulerframework.NodeInfo) []PredicateFailureReason {
	admissionResults := over_scheduler.AdmissionCheck(pod, nodeInfo, true) // 对 noderesources/nodeport/nodeAffinity/nodename 做一些检查  ✅
	var reasons []PredicateFailureReason
	for _, r := range admissionResults {
		if r.InsufficientResource != nil {
			reasons = append(reasons, &InsufficientResourceError{
				ResourceName: r.InsufficientResource.ResourceName,
				Requested:    r.InsufficientResource.Requested,
				Used:         r.InsufficientResource.Used,
				Capacity:     r.InsufficientResource.Capacity,
			})
		} else {
			reasons = append(reasons, &PredicateFailureError{r.Name, r.Reason})
		}
	}

	// Check taint/toleration except for static pods
	if !types.IsStaticPod(pod) {
		// 普通pod
		_, isUntolerated := corev1.FindMatchingUntoleratedTaint(nodeInfo.Node().Spec.Taints, pod.Spec.Tolerations, func(t *v1.Taint) bool {
			// Kubelet is only interested in the NoExecute taint.
			return t.Effect == v1.TaintEffectNoExecute
		})
		if isUntolerated {
			reasons = append(reasons, &PredicateFailureError{tainttoleration.Name, tainttoleration.ErrReasonNotMatch})
		}
	}

	return reasons
}
