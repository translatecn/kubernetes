/*
Copyright 2019 The Kubernetes Authors.

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

package devicemanager

import (
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	pluginapi "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
	"k8s.io/kubernetes/pkg/kubelet/cm/topologymanager"
	"k8s.io/kubernetes/pkg/kubelet/cm/topologymanager/bitmask"
)

func (m *ManagerImpl) getAvailableDevices(resource string) sets.String {
	// 从健康设备列表中移除所有正在使用的设备.
	return m.healthyDevices[resource].Difference(m.allocatedDevices[resource])
}

func (m *ManagerImpl) generateDeviceTopologyHints(resource string, available sets.String, reusable sets.String, request int) []topologymanager.TopologyHint {
	// 初始化minAffinitySize以包含所有NUMA节点
	minAffinitySize := len(m.numaNodes)

	// 遍历所有 NUMA 节点的组合,并从中构建拓扑提示.
	var hints []topologymanager.TopologyHint
	bitmask.IterateBitMasks(m.numaNodes, func(mask bitmask.BitMask) { // 从 0~len(m.numaNodes),所有元素的组合
		// 首先,根据当前请求的大小更新 minAffinitySize.
		devicesInMask := 0
		for _, device := range m.allDevices[resource] {
			if mask.AnySet(m.getNUMANodeIds(device.Topology)) { // mask 包含 该device所属的numa node 的一个
				devicesInMask++ // 该numa组合下,包含多少个设备
			}
		}
		if devicesInMask >= request && mask.Count() < minAffinitySize {
			// 记录 不同 numa 组合,最满足请求的资源情况
			minAffinitySize = mask.Count()
		}

		// Then check to see if all of the reusable devices are part of the bitmask.
		// 检查所有可重复使用的设备是否都属于位掩码（bitmask）的一部分.
		numMatching := 0 // numa组合 包含多少个 可重用的设备
		for d := range reusable {
			// Skip the device if it doesn't specify any topology info.
			if m.allDevices[resource][d].Topology == nil {
				continue
			}
			// Otherwise disregard this mask if its NUMANode isn't part of it.
			if !mask.AnySet(m.getNUMANodeIds(m.allDevices[resource][d].Topology)) {
				return
			}
			numMatching++
		}

		// 检查当前NUMA节点组合上是否有足够的可用设备来满足设备请求.
		for d := range available {
			if mask.AnySet(m.getNUMANodeIds(m.allDevices[resource][d].Topology)) {
				numMatching++
			}
		}

		// 如果没有足够的可用设备来满足设备请求,则继续尝试下一个组合.
		if numMatching < request {
			return
		}
		// 否则,从NUMA掩码创建一个新的提示,并将其添加到提示列表中.在第一次遍历时,我们将所有提示首选项设置为“false”.
		hints = append(hints, topologymanager.TopologyHint{
			NUMANodeAffinity: mask,
			Preferred:        false,
		})
	})
	// 符合所需设备的所有拓扑组合
	for i := range hints {
		if hints[i].NUMANodeAffinity.Count() == minAffinitySize {
			hints[i].Preferred = true
		}
	}

	return hints
}

func (m *ManagerImpl) getNUMANodeIds(topology *pluginapi.TopologyInfo) []int {
	if topology == nil {
		return nil
	}
	var ids []int
	for _, n := range topology.Nodes {
		ids = append(ids, int(n.ID))
	}
	return ids
}

func (m *ManagerImpl) getPodDeviceRequest(pod *v1.Pod) map[string]int {
	podResources := sets.NewString()

	// Find the max request of a given resource across all init containers
	initContainerRequests := make(map[string]int)
	for _, container := range pod.Spec.InitContainers {
		for resourceObj, requestedObj := range container.Resources.Limits {
			resource := string(resourceObj)
			requested := int(requestedObj.Value())

			if !m.isDevicePluginResource(resource) {
				continue
			}

			podResources.Insert(resource)

			if _, exists := initContainerRequests[resource]; !exists {
				initContainerRequests[resource] = requested
				continue
			}
			if requested > initContainerRequests[resource] {
				initContainerRequests[resource] = requested

			}
		}
	}

	// Compute the sum of requests across all app containers for a given resource
	appContainerRequests := make(map[string]int)
	for _, container := range pod.Spec.Containers {
		for resourceObj, requestedObj := range container.Resources.Limits {
			resource := string(resourceObj)
			requested := int(requestedObj.Value())

			if !m.isDevicePluginResource(resource) {
				continue
			}
			podResources.Insert(resource)
			appContainerRequests[resource] += requested
		}
	}

	// Calculate podRequests as the max of init and app container requests for a given resource
	podRequests := make(map[string]int)
	for resource := range podResources {
		_, initExists := initContainerRequests[resource]
		_, appExists := appContainerRequests[resource]

		if initExists && !appExists {
			podRequests[resource] = initContainerRequests[resource]
			continue
		}

		if !initExists && appExists {
			podRequests[resource] = appContainerRequests[resource]
			continue
		}

		if initContainerRequests[resource] > appContainerRequests[resource] {
			podRequests[resource] = initContainerRequests[resource]
			continue
		}

		podRequests[resource] = appContainerRequests[resource]
	}

	return podRequests
}

func (m *ManagerImpl) deviceHasTopologyAlignment(resource string) bool {
	// 如果任何设备都有可用的拓扑numodes,我们假设它们关心对齐.
	for _, device := range m.allDevices[resource] {
		if device.Topology != nil && len(device.Topology.Nodes) > 0 {
			return true
		}
	}
	return false
}

func (m *ManagerImpl) GetTopologyHints(pod *v1.Pod, container *v1.Container) map[string][]topologymanager.TopologyHint { // ✅   Device
	m.setPodPendingAdmission(pod)
	m.UpdateAllocatedDevices() // ✅

	// Loop through all device resources and generate TopologyHints for them..
	deviceHints := make(map[string][]topologymanager.TopologyHint)
	for resourceObj, requestedObj := range container.Resources.Limits {
		resource := string(resourceObj)
		requested := int(requestedObj.Value())

		// 只考虑与设备插件相关的资源.
		if m.isDevicePluginResource(resource) {
			// 只考虑实际包含拓扑信息的设备.
			if aligned := m.deviceHasTopologyAlignment(resource); !aligned {
				klog.InfoS("资源没有拓扑首选项", "resource", resource)
				deviceHints[resource] = nil
				continue
			}

			// 如果容器已经有设备资源分配了,那么就可以跳过重新生成提示的过程,直接使用之前生成的提示.
			allocated := m.podDevices.containerDevices(string(pod.UID), container.Name, resource)
			if allocated.Len() > 0 {
				if allocated.Len() != requested {
					klog.ErrorS(nil, "资源已经被分配给一个 Pod,但该 Pod 的编号与请求的编号不同.", "resource", resource, "pod", klog.KObj(pod), "containerName", container.Name, "request", requested, "allocated", allocated.Len())
					deviceHints[resource] = []topologymanager.TopologyHint{}
					continue
				}
				klog.InfoS("为已经分配给 Pod 的资源重新生成拓扑提示", "resource", resource, "pod", klog.KObj(pod), "containerName", container.Name)
				deviceHints[resource] = m.generateDeviceTopologyHints(resource, allocated, sets.String{}, requested)
				continue
			}

			available := m.getAvailableDevices(resource)
			reusable := m.devicesToReuse[string(pod.UID)][resource]
			if available.Union(reusable).Len() < requested {
				klog.ErrorS(nil, "无法生成拓扑提示（TopologyHints）,因为所请求的设备数量不可用.", "resource", resource, "request", requested, "available", available.Union(reusable).Len())
				deviceHints[resource] = []topologymanager.TopologyHint{}
				continue
			}

			// 根据当前的请求大小和可用设备列表,为该资源生成拓扑提示（TopologyHints）.
			deviceHints[resource] = m.generateDeviceTopologyHints(resource, available, reusable, requested)
		}
	}

	return deviceHints
}

func (m *ManagerImpl) GetPodTopologyHints(pod *v1.Pod) map[string][]topologymanager.TopologyHint {
	m.setPodPendingAdmission(pod)
	m.UpdateAllocatedDevices()

	deviceHints := make(map[string][]topologymanager.TopologyHint)
	accumulatedResourceRequests := m.getPodDeviceRequest(pod)

	for resource, requested := range accumulatedResourceRequests {
		// Only consider devices that actually contain topology information.
		if aligned := m.deviceHasTopologyAlignment(resource); !aligned {
			klog.InfoS("Resource does not have a topology preference", "resource", resource)
			deviceHints[resource] = nil
			continue
		}

		// Short circuit to regenerate the same hints if there are already
		// devices allocated to the Pod. This might happen after a
		// kubelet restart, for example.
		allocated := m.podDevices.podDevices(string(pod.UID), resource)
		if allocated.Len() > 0 {
			if allocated.Len() != requested {
				klog.ErrorS(nil, "Resource already allocated to pod with different number than request", "resource", resource, "pod", klog.KObj(pod), "request", requested, "allocated", allocated.Len())
				deviceHints[resource] = []topologymanager.TopologyHint{}
				continue
			}
			klog.InfoS("Regenerating TopologyHints for resource already allocated to pod", "resource", resource, "pod", klog.KObj(pod))
			deviceHints[resource] = m.generateDeviceTopologyHints(resource, allocated, sets.String{}, requested)
			continue
		}

		// Get the list of available devices, for which TopologyHints should be generated.
		available := m.getAvailableDevices(resource)
		if available.Len() < requested {
			klog.ErrorS(nil, "Unable to generate topology hints: requested number of devices unavailable", "resource", resource, "request", requested, "available", available.Len())
			deviceHints[resource] = []topologymanager.TopologyHint{}
			continue
		}

		// Generate TopologyHints for this resource given the current
		// request size and the list of available devices.
		deviceHints[resource] = m.generateDeviceTopologyHints(resource, available, sets.String{}, requested)
	}

	return deviceHints
}
