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

package status

import (
	"fmt"
	"strings"

	v1 "k8s.io/api/core/v1"
	podutil "k8s.io/kubernetes/pkg/api/v1/pod"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	runtimeutil "k8s.io/kubernetes/pkg/kubelet/kuberuntime/util"
	kubetypes "k8s.io/kubernetes/pkg/kubelet/types"
)

const (
	UnknownContainerStatuses = "UnknownContainerStatuses" // 所有容器状态都是未知的。
	PodCompleted             = "PodCompleted"             // 所有相关容器已成功。
	PodFailed                = "PodFailed"                // 容器失败
	ContainersNotReady       = "ContainersNotReady"       // 至少一个容器 没 ready
	ContainersNotInitialized = "ContainersNotInitialized" // 至少一个init容器没成功
	ReadinessGatesNotReady   = "ReadinessGatesNotReady"   // 至少一个容器的 readiness 没ready
)

func GenerateContainersReadyCondition(spec *v1.PodSpec, containerStatuses []v1.ContainerStatus, podPhase v1.PodPhase) v1.PodCondition { // ✅

	// 容器就绪状态是指容器是否已经准备好开始处理请求
	// 如果containerStatuses（容器状态）为空，则代表肯定没有ready，直接status返回false
	if containerStatuses == nil {
		return v1.PodCondition{
			Type:   v1.ContainersReady,
			Status: v1.ConditionFalse,
			Reason: UnknownContainerStatuses,
		}
	}
	unknownContainers := []string{}
	unreadyContainers := []string{}
	for _, container := range spec.Containers {
		if containerStatus, ok := podutil.GetContainerStatus(containerStatuses, container.Name); ok {
			if !containerStatus.Ready {
				unreadyContainers = append(unreadyContainers, container.Name)
			}
		} else {
			unknownContainers = append(unknownContainers, container.Name)
		}
	}

	// If all containers are known and succeeded, just return PodCompleted.
	if podPhase == v1.PodSucceeded && len(unknownContainers) == 0 {
		//如果容器已经运行完成了（源码中会显示Succeeded，kubectl会显示Completed）并且没有没启动的容器，则返回未就绪，原因是已完成
		return generateContainersReadyConditionForTerminalPhase(podPhase)
	}

	// 如果pod阶段失败，则显式地将容器的就绪条件设置为false，因为它们可能正在终止。
	if podPhase == v1.PodFailed {
		return generateContainersReadyConditionForTerminalPhase(podPhase)
	}

	// Generate message for containers in unknown condition.
	unreadyMessages := []string{}
	if len(unknownContainers) > 0 {
		unreadyMessages = append(unreadyMessages, fmt.Sprintf("containers with unknown status: %s", unknownContainers))
	}
	if len(unreadyContainers) > 0 {
		unreadyMessages = append(unreadyMessages, fmt.Sprintf("containers with unready status: %s", unreadyContainers))
	}
	unreadyMessage := strings.Join(unreadyMessages, ", ")
	if unreadyMessage != "" {
		return v1.PodCondition{
			Type:    v1.ContainersReady,
			Status:  v1.ConditionFalse,
			Reason:  ContainersNotReady,
			Message: unreadyMessage,
		}
	}

	return v1.PodCondition{
		Type:   v1.ContainersReady,
		Status: v1.ConditionTrue,
	}
}

func GeneratePodReadyCondition(spec *v1.PodSpec, conditions []v1.PodCondition, containerStatuses []v1.ContainerStatus, podPhase v1.PodPhase) v1.PodCondition { // ✅
	// 返回包含此pod当前状态的详细信息。
	containersReady := GenerateContainersReadyCondition(spec, containerStatuses, podPhase) // 容器是否已经准备好开始处理请求 ✅
	if containersReady.Status != v1.ConditionTrue {
		return v1.PodCondition{
			Type:    v1.PodReady,
			Status:  containersReady.Status,
			Reason:  containersReady.Reason,
			Message: containersReady.Message,
		}
	}

	// Evaluate corresponding conditions specified in readiness gate
	// Generate message if any readiness gate is not satisfied.
	unreadyMessages := []string{}
	for _, rg := range spec.ReadinessGates {
		_, c := podutil.GetPodConditionFromList(conditions, rg.ConditionType)
		if c == nil {
			unreadyMessages = append(unreadyMessages, fmt.Sprintf("corresponding condition of pod readiness gate %q does not exist.", string(rg.ConditionType)))
		} else if c.Status != v1.ConditionTrue {
			unreadyMessages = append(unreadyMessages, fmt.Sprintf("the status of pod readiness gate %q is not \"True\", but %v", string(rg.ConditionType), c.Status))
		}
	}

	// Set "Ready" condition to "False" if any readiness gate is not ready.
	if len(unreadyMessages) != 0 {
		unreadyMessage := strings.Join(unreadyMessages, ", ")
		return v1.PodCondition{
			Type:    v1.PodReady,
			Status:  v1.ConditionFalse,
			Reason:  ReadinessGatesNotReady,
			Message: unreadyMessage,
		}
	}

	return v1.PodCondition{
		Type:   v1.PodReady,
		Status: v1.ConditionTrue,
	}
}

// GeneratePodInitializedCondition returns initialized condition if all init containers in a pod are ready, else it
// returns an uninitialized condition.
func GeneratePodInitializedCondition(spec *v1.PodSpec, containerStatuses []v1.ContainerStatus, podPhase v1.PodPhase) v1.PodCondition {
	// Find if all containers are ready or not.
	if containerStatuses == nil && len(spec.InitContainers) > 0 {
		return v1.PodCondition{
			Type:   v1.PodInitialized,
			Status: v1.ConditionFalse,
			Reason: UnknownContainerStatuses,
		}
	}
	unknownContainers := []string{}
	unreadyContainers := []string{}
	for _, container := range spec.InitContainers {
		if containerStatus, ok := podutil.GetContainerStatus(containerStatuses, container.Name); ok {
			if !containerStatus.Ready {
				unreadyContainers = append(unreadyContainers, container.Name)
			}
		} else {
			unknownContainers = append(unknownContainers, container.Name)
		}
	}

	// If all init containers are known and succeeded, just return PodCompleted.
	if podPhase == v1.PodSucceeded && len(unknownContainers) == 0 {
		return v1.PodCondition{
			Type:   v1.PodInitialized,
			Status: v1.ConditionTrue,
			Reason: PodCompleted,
		}
	}

	unreadyMessages := []string{}
	if len(unknownContainers) > 0 {
		unreadyMessages = append(unreadyMessages, fmt.Sprintf("containers with unknown status: %s", unknownContainers))
	}
	if len(unreadyContainers) > 0 {
		unreadyMessages = append(unreadyMessages, fmt.Sprintf("containers with incomplete status: %s", unreadyContainers))
	}
	unreadyMessage := strings.Join(unreadyMessages, ", ")
	if unreadyMessage != "" {
		return v1.PodCondition{
			Type:    v1.PodInitialized,
			Status:  v1.ConditionFalse,
			Reason:  ContainersNotInitialized,
			Message: unreadyMessage,
		}
	}

	return v1.PodCondition{
		Type:   v1.PodInitialized,
		Status: v1.ConditionTrue,
	}
}

func GeneratePodHasNetworkCondition(pod *v1.Pod, podStatus *kubecontainer.PodStatus) v1.PodCondition {
	newSandboxNeeded, _, _ := runtimeutil.PodSandboxChanged(pod, podStatus)
	// if a new sandbox does not need to be created for a pod, it indicates that
	// a sandbox for the pod with networking configured already exists.
	// Otherwise, the kubelet needs to invoke the container runtime to create a
	// fresh sandbox and configure networking for the sandbox.
	if !newSandboxNeeded {
		return v1.PodCondition{
			Type:   kubetypes.PodHasNetwork,
			Status: v1.ConditionTrue,
		}
	}
	return v1.PodCondition{
		Type:   kubetypes.PodHasNetwork,
		Status: v1.ConditionFalse,
	}
}

func generateContainersReadyConditionForTerminalPhase(podPhase v1.PodPhase) v1.PodCondition {
	condition := v1.PodCondition{
		Type:   v1.ContainersReady,
		Status: v1.ConditionFalse,
	}

	if podPhase == v1.PodFailed {
		condition.Reason = PodFailed
	} else if podPhase == v1.PodSucceeded {
		condition.Reason = PodCompleted
	}

	return condition
}

func generatePodReadyConditionForTerminalPhase(podPhase v1.PodPhase) v1.PodCondition {
	condition := v1.PodCondition{
		Type:   v1.PodReady,
		Status: v1.ConditionFalse,
	}

	if podPhase == v1.PodFailed {
		condition.Reason = PodFailed
	} else if podPhase == v1.PodSucceeded {
		condition.Reason = PodCompleted
	}

	return condition
}
