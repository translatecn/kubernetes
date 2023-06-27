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

package devicemanager

import (
	"context"
	"fmt"
	"k8s.io/kubernetes/pkg/kubelet/pluginmanager/cache"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	cadvisorapi "github.com/google/cadvisor/info/v1"
	"k8s.io/klog/v2"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	errorsutil "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	pluginapi "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
	"k8s.io/kubernetes/pkg/kubelet/checkpointmanager"
	"k8s.io/kubernetes/pkg/kubelet/checkpointmanager/errors"
	"k8s.io/kubernetes/pkg/kubelet/cm/devicemanager/checkpoint"
	plugin "k8s.io/kubernetes/pkg/kubelet/cm/devicemanager/plugin/v1beta1"
	"k8s.io/kubernetes/pkg/kubelet/cm/topologymanager"
	"k8s.io/kubernetes/pkg/kubelet/config"
	"k8s.io/kubernetes/pkg/kubelet/lifecycle"
	"k8s.io/kubernetes/pkg/kubelet/metrics"
	schedulerframework "k8s.io/kubernetes/pkg/scheduler/framework"
)

const nodeWithoutTopology = -1

// ActivePodsFunc is a function that returns a list of pods to reconcile.
type ActivePodsFunc func() []*v1.Pod

// ManagerImpl is the structure in charge of managing Device Plugins.
type ManagerImpl struct {
	checkpointdir         string                              // /var/lib/kubelet/device-plugins
	endpoints             map[string]endpointInfo             // Key is ResourceName
	mutex                 sync.Mutex                          //
	server                plugin.Server                       //
	activePods            ActivePodsFunc                      //
	sourcesReady          config.SourcesReady                 // kubelet配置源的就绪状态,确定何时可以从检查点状态中清除不活动的Pod
	allDevices            ResourceDeviceInstances             // 保存当前注册到设备管理器的所有设备
	healthyDevices        map[string]sets.String              // 资源名:[设备1,...]
	unhealthyDevices      map[string]sets.String              // 资源名:[设备1,...]
	allocatedDevices      map[string]sets.String              // 已经使用的设备  ,key:resourceName
	podDevices            *podDevices                         // 包含pod到已分配设备的映射.
	checkpointManager     checkpointmanager.CheckpointManager //
	numaNodes             []int                               // 物理CPU 序号
	topologyAffinityStore topologymanager.Store               // 设备管理器可以查询的拓扑亲和性的存储.
	devicesToReuse        PodReusableDevices                  // 包含每个pod 可以重用的设备,因为它们已分配给初始化容器.
	pendingAdmissionPod   *v1.Pod                             // 当前在准入阶段的pod
}

type endpointInfo struct {
	e    endpoint
	opts *pluginapi.DevicePluginOptions
}

type sourcesReadyStub struct{}

// PodReusableDevices is a map by pod name of devices to reuse.
type PodReusableDevices map[string]map[string]sets.String

// UpdatePluginResources 基于已经分配给pod的设备信息 更新节点资源.
func (m *ManagerImpl) UpdatePluginResources(node *schedulerframework.NodeInfo, attrs *lifecycle.PodAdmitAttributes) error {
	pod := attrs.Pod

	if !m.podDevices.hasPod(string(pod.UID)) {
		return nil
	}
	// 刚创建时,不会走
	m.sanitizeNodeAllocatable(node)
	return nil
}

// GetCapacity 函数在Kubelet更新其节点状态时被调用.
// 第一个返回变量包含注册的设备插件资源容量.
// 第二个返回变量包含注册的设备插件资源可分配量.
// 第三个返回变量包含先前注册的不再活动的资源.
// Kubelet使用此信息来更新其节点状态中的资源容量/可分配量.
// 在调用之后,设备插件可以从其内部列表中删除不活动的资源,因为更改已经在Kubelet节点状态中反映出来.
// 需要注意的是,在Kubelet重新启动的特殊情况下,设备插件资源容量可能暂时降为零,直到相应的设备插件重新注册.
// 这是可以接受的,因为在谓词Admit期间运行cm.UpdatePluginResource()可以保证我们调整nodeinfo容量以适应已分配的pod,以便它们可以继续运行.然而,需要设备插件资源的新pod将无法调度,直到设备插件重新注册.
func (m *ManagerImpl) GetCapacity() (v1.ResourceMap, v1.ResourceMap, []string) {
	needsUpdateCheckpoint := false
	var capacity = v1.ResourceMap{}
	var allocatable = v1.ResourceMap{}
	deletedResources := sets.NewString()
	m.mutex.Lock()
	for resourceName, devices := range m.healthyDevices {
		eI, ok := m.endpoints[resourceName]
		if (ok && eI.e.stopGracePeriodExpired()) || !ok {
			// endpoints和(un)healthyDevices中包含的资源应始终保持一致.否则,我们有可能无法清理不存在的资源或设备.
			if !ok {
				klog.ErrorS(nil, "Unexpected: healthyDevices and endpoints are out of sync")
			}
			delete(m.endpoints, resourceName)
			delete(m.healthyDevices, resourceName)
			deletedResources.Insert(resourceName)
			needsUpdateCheckpoint = true
		} else {
			capacity[v1.ResourceName(resourceName)] = *resource.NewQuantity(int64(devices.Len()), resource.DecimalSI)
			allocatable[v1.ResourceName(resourceName)] = *resource.NewQuantity(int64(devices.Len()), resource.DecimalSI)
		}
	}
	for resourceName, devices := range m.unhealthyDevices {
		eI, ok := m.endpoints[resourceName]
		if (ok && eI.e.stopGracePeriodExpired()) || !ok {
			if !ok {
				klog.ErrorS(nil, "Unexpected: unhealthyDevices and endpoints are out of sync")
			}
			delete(m.endpoints, resourceName)
			delete(m.unhealthyDevices, resourceName)
			deletedResources.Insert(resourceName)
			needsUpdateCheckpoint = true
		} else {
			capacityCount := capacity[v1.ResourceName(resourceName)]
			unhealthyCount := *resource.NewQuantity(int64(devices.Len()), resource.DecimalSI)
			capacityCount.Add(unhealthyCount)
			capacity[v1.ResourceName(resourceName)] = capacityCount
		}
	}
	m.mutex.Unlock()
	if needsUpdateCheckpoint {
		if err := m.writeCheckpoint(); err != nil {
			klog.ErrorS(err, "Error on writing checkpoint")
		}
	}
	return capacity, allocatable, deletedResources.UnsortedList()
}

// GetDeviceRunContainerOptions checks whether we have cached containerDevices
// for the passed-in <pod, container> and returns its DeviceRunContainerOptions
// for the found one. An empty struct is returned in case no cached state is found.
// 检查我们是否有针对传入的<pod, container>缓存的containerDevices,并返回找到的DeviceRunContainerOptions.如果没有找到缓存状态,将返回一个空的结构体.
func (m *ManagerImpl) GetDeviceRunContainerOptions(pod *v1.Pod, container *v1.Container) (*DeviceRunContainerOptions, error) {
	podUID := string(pod.UID)
	contName := container.Name
	needsReAllocate := false
	for k, v := range container.Resources.Limits {
		resource := string(k)
		if !m.isDevicePluginResource(resource) || v.Value() == 0 {
			continue
		}
		err := m.callPreStartContainerIfNeeded(podUID, contName, resource)
		if err != nil {
			return nil, err
		}

		if !m.checkPodActive(pod) {
			klog.ErrorS(nil, "pod deleted from activePods, skip to reAllocate", "podUID", podUID)
			continue
		}

		// This is a device plugin resource yet we don't have cached
		// resource state. This is likely due to a race during node
		// restart. We re-issue allocate request to cover this race.
		// 获取给定容器某种资源的设备分配情况
		if m.podDevices.containerDevices(podUID, contName, resource) == nil {
			needsReAllocate = true
		}
	}
	if needsReAllocate {
		klog.V(2).InfoS("Needs to re-allocate device plugin resources for pod", "pod", klog.KObj(pod), "containerName", container.Name)
		if err := m.Allocate(pod, container); err != nil {
			return nil, err
		}
	}

	return m.podDevices.deviceRunContainerOptions(string(pod.UID), container.Name), nil // 已经从设备插件分配了资源,返回将资源应用到pod的配置
}

// callPreStartContainerIfNeeded issues PreStartContainer grpc call for device plugin resource
// with PreStartRequired option set.
func (m *ManagerImpl) callPreStartContainerIfNeeded(podUID, contName, resource string) error {
	m.mutex.Lock()
	eI, ok := m.endpoints[resource]
	if !ok {
		m.mutex.Unlock()
		return fmt.Errorf("endpoint not found in cache for a registered resource: %s", resource)
	}

	if eI.opts == nil || !eI.opts.PreStartRequired {
		m.mutex.Unlock()
		klog.V(4).InfoS("跳过资源的PreStartContainer", "resourceName", resource)
		return nil
	}

	devices := m.podDevices.containerDevices(podUID, contName, resource)
	if devices == nil {
		m.mutex.Unlock()
		return fmt.Errorf("no devices found allocated in local cache for pod %s, container %s, resource %s", string(podUID), contName, resource)
	}

	m.mutex.Unlock()
	devs := devices.UnsortedList()
	klog.V(4).InfoS("Issuing a PreStartContainer call for container", "containerName", contName, "podUID", string(podUID))
	_, err := eI.e.preStartContainer(devs)
	if err != nil {
		return fmt.Errorf("device plugin PreStartContainer rpc failed with err: %v", err)
	}
	// TODO: Add metrics support for init RPC
	return nil
}

// 与设备插件进行通信,并了解设备插件是否支持获取首选设备分配信息的功能.
func (m *ManagerImpl) callGetPreferredAllocationIfAvailable(podUID, contName, resource string, available, mustInclude sets.String, size int) (sets.String, error) {
	eI, ok := m.endpoints[resource]
	if !ok {
		return nil, fmt.Errorf("在已注册的资源的缓存中找不到对应的端点.%s", resource)
	}

	if eI.opts == nil || !eI.opts.GetPreferredAllocationAvailable {
		klog.V(4).InfoS("插件选项指示跳过对资源的GetPreferredAllocation调用.", "resourceName", resource)
		return nil, nil
	}

	m.mutex.Unlock()
	klog.V(4).InfoS("调用GetPreferredAllocation来获取容器的首选分配信息", "containerName", contName, "podUID", string(podUID))
	resp, err := eI.e.getPreferredAllocation(available.UnsortedList(), mustInclude.UnsortedList(), size)
	m.mutex.Lock()
	if err != nil {
		return nil, fmt.Errorf("device plugin GetPreferredAllocation rpc failed with err: %v", err)
	}
	if resp != nil && len(resp.ContainerResponses) > 0 {
		return sets.NewString(resp.ContainerResponses[0].DeviceIDs...), nil
	}
	return sets.NewString(), nil
}

// sanitizeNodeAllocatable 在设备管理器中扫描 allocatedDevices,
// 如果有必要,更新nodeInfo中的allocatableResource,使其至少等于已分配的容量.
// 这允许已经在节点上调度的pod即使在设备插件失败时也能通过GeneralPredicates准入检查.
func (m *ManagerImpl) sanitizeNodeAllocatable(node *schedulerframework.NodeInfo) {
	var newAllocatableResource *schedulerframework.Resource
	allocatableResource := node.Allocatable // 表示节点可用于调度的资源.
	if allocatableResource.ScalarResources == nil {
		allocatableResource.ScalarResources = make(map[v1.ResourceName]int64)
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()
	for resource, devices := range m.allocatedDevices { // 已经使用的设备
		needed := devices.Len()
		quant, ok := allocatableResource.ScalarResources[v1.ResourceName(resource)]
		if ok && int(quant) >= needed {
			continue
		}
		// Needs to update nodeInfo.AllocatableResource to make sure
		// NodeInfo.allocatableResource at least equal to the capacity already allocated.
		if newAllocatableResource == nil {
			newAllocatableResource = allocatableResource.Clone()
		}
		newAllocatableResource.ScalarResources[v1.ResourceName(resource)] = int64(needed)
	}
	if newAllocatableResource != nil {
		node.Allocatable = newAllocatableResource
	}
}

// GetAllocatableDevices returns information about all the healthy devices known to the manager
func (m *ManagerImpl) GetAllocatableDevices() ResourceDeviceInstances {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	resp := m.allDevices.Filter(m.healthyDevices)
	klog.V(4).InfoS("GetAllocatableDevices", "known", len(m.allDevices), "allocatable", len(resp))
	return resp
}

// GetDevices returns the devices used by the specified container
func (m *ManagerImpl) GetDevices(podUID, containerName string) ResourceDeviceInstances {
	return m.podDevices.getContainerDevices(podUID, containerName)
}

// NewManagerImpl creates a new manager.
func NewManagerImpl(topology []cadvisorapi.Node, topologyAffinityStore topologymanager.Store) (*ManagerImpl, error) {
	socketPath := pluginapi.KubeletSocket
	if runtime.GOOS == "windows" {
		socketPath = os.Getenv("SYSTEMDRIVE") + pluginapi.KubeletSocketWindows
	}
	return newManagerImpl(socketPath, topology, topologyAffinityStore)
}

func newManagerImpl(socketPath string, topology []cadvisorapi.Node, topologyAffinityStore topologymanager.Store) (*ManagerImpl, error) {
	klog.V(2).InfoS("Creating Device Plugin manager", "path", socketPath)

	var numaNodes []int
	for _, node := range topology {
		numaNodes = append(numaNodes, node.Id)
	}

	manager := &ManagerImpl{
		endpoints:             make(map[string]endpointInfo),
		allDevices:            NewResourceDeviceInstances(),
		healthyDevices:        make(map[string]sets.String),
		unhealthyDevices:      make(map[string]sets.String),
		allocatedDevices:      make(map[string]sets.String),
		podDevices:            newPodDevices(),
		numaNodes:             numaNodes,
		topologyAffinityStore: topologyAffinityStore,
		devicesToReuse:        make(PodReusableDevices),
	}

	server, err := plugin.NewServer(socketPath, manager, manager)
	if err != nil {
		return nil, fmt.Errorf("failed to create plugin server: %v", err)
	}

	manager.server = server
	manager.checkpointdir, _ = filepath.Split(server.SocketPath()) // /var/lib/kubelet/device-plugins

	// The following structures are populated with real implementations in manager.Start()
	// Before that, initializes them to perform no-op operations.
	manager.activePods = func() []*v1.Pod { return []*v1.Pod{} }
	manager.sourcesReady = &sourcesReadyStub{}
	checkpointManager, err := checkpointmanager.NewCheckpointManager(manager.checkpointdir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize checkpoint manager: %v", err)
	}
	manager.checkpointManager = checkpointManager

	return manager, nil
}

// Allocate 分配已注册插件的资源
func (m *ManagerImpl) Allocate(pod *v1.Pod, container *v1.Container) error {
	// Allocate->allocateContainerResources->eI.e.allocate(devs)

	// pod 在准入阶段,应该先保存它,避免在结束前 丢失数据
	m.setPodPendingAdmission(pod)

	if _, ok := m.devicesToReuse[string(pod.UID)]; !ok {
		m.devicesToReuse[string(pod.UID)] = make(map[string]sets.String)
	}
	// 如果m.devicesToReuse中存在当前pod以外的pod条目,请删除它们.
	for podUID := range m.devicesToReuse {
		if podUID != string(pod.UID) {
			delete(m.devicesToReuse, podUID)
		}
	}
	//首先为init容器分配资源,因为我们知道调用者总是在遍历应用程序容器之前循环遍历init容器.如果调用者更改了这些语义,则需要修改此逻辑.
	for _, initContainer := range pod.Spec.InitContainers {
		if container.Name == initContainer.Name {
			if err := m.allocateContainerResources(pod, container, m.devicesToReuse[string(pod.UID)]); err != nil {
				return err
			}
			// 对于initContainer,将所分配的device不断地加入到devicesToReuse列表中,以便提供给container使用
			m.podDevices.addContainerAllocatedResources(string(pod.UID), container.Name, m.devicesToReuse[string(pod.UID)])
			return nil
		}
	}
	if err := m.allocateContainerResources(pod, container, m.devicesToReuse[string(pod.UID)]); err != nil {
		return err
	}
	// 而对于container,则不断地从可重用设置列表中将分配出去的设备删除
	m.podDevices.removeContainerAllocatedResources(string(pod.UID), container.Name, m.devicesToReuse[string(pod.UID)]) //
	return nil
}

func (m *ManagerImpl) isDevicePluginResource(resource string) bool {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	_, registeredResource := m.healthyDevices[resource]
	_, allocatedResource := m.allocatedDevices[resource]
	// Return true if this is either an active device plugin resource or
	// a resource we have previously allocated.
	if registeredResource || allocatedResource {
		return true
	}
	return false
}

// UpdateAllocatedDevices 删除所有处于终结状态的pod,并回收其占用的资源,所以有时会在kubelet的日志中看到pods to be removed:xxxx字样
func (m *ManagerImpl) UpdateAllocatedDevices() {
	if !m.sourcesReady.AllReady() { // kubelet配置源的就绪状态
		return
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	activeAndAdmittedPods := m.activePods()
	if m.pendingAdmissionPod != nil {
		activeAndAdmittedPods = append(activeAndAdmittedPods, m.pendingAdmissionPod)
	}

	podsToBeRemoved := m.podDevices.pods()
	for _, pod := range activeAndAdmittedPods {
		podsToBeRemoved.Delete(string(pod.UID))
	}
	if len(podsToBeRemoved) <= 0 {
		return
	}
	klog.V(3).InfoS("Pods to be removed", "podUIDs", podsToBeRemoved.List())
	m.podDevices.delete(podsToBeRemoved.List()) // 移除不存在的pod占用的设备
	m.allocatedDevices = m.podDevices.devices() // 在更新了Pod的分配信息之后,重新生成已分配设备
}

func (m *ManagerImpl) setPodPendingAdmission(pod *v1.Pod) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.pendingAdmissionPod = pod
}

// 根据NUMA亲和性进行设备筛选的操作.在设备分配过程中,可能会根据NUMA节点的亲和性来选择合适的设备.通过筛选可用的设备,可以确保将设备分配给与容器或任务具有相同NUMA节点亲和性的节点,以提高性能和效率.
func (m *ManagerImpl) filterByAffinity(podUID, containerName, resource string, available sets.String) (aligned, unaligned, noAffinity sets.String) {
	// 如果没有可用的对齐信息,那么就直接将可用的设备列表返回.
	hint := m.topologyAffinityStore.GetAffinity(podUID, containerName)
	// 判断这种资源是不是需要numa对齐
	if !m.deviceHasTopologyAlignment(resource) || hint.NUMANodeAffinity == nil {
		return sets.NewString(), sets.NewString(), available
	}
	// 建立NUMA节点到与其相关联的设备的映射.一个设备可以同时关联多个NUMA节点.
	// 如果一个可用的设备没有任何NUMA节点与它相关联,将它添加到一个NUMA节点列表中,为假的NUMANode -1.
	perNodeDevices := make(map[int]sets.String)
	for d := range available {
		if m.allDevices[resource][d].Topology == nil || len(m.allDevices[resource][d].Topology.Nodes) == 0 {
			if _, ok := perNodeDevices[nodeWithoutTopology]; !ok {
				perNodeDevices[nodeWithoutTopology] = sets.NewString()
			}
			perNodeDevices[nodeWithoutTopology].Insert(d)
			continue
		}

		for _, node := range m.allDevices[resource][d].Topology.Nodes {
			if _, ok := perNodeDevices[int(node.ID)]; !ok {
				perNodeDevices[int(node.ID)] = sets.NewString()
			}
			perNodeDevices[int(node.ID)].Insert(d)
		}
	}

	// Get a flat list of all of the nodes associated with available devices.
	var nodes []int
	for node := range perNodeDevices {
		nodes = append(nodes, node)
	}

	// 这段代码的作用是对节点列表进行排序.排序规则如下：
	//
	//1) 首先将节点列表中与给定的'hint'节点亲和性集合中包含的节点排在前面.
	//2) 然后将节点列表中与给定的'hint'节点亲和性集合中不包含的节点排在后面.
	//3) 如果列表中包含一个虚拟的NUMANode节点编号为-1的节点（假设存在）,将其排在最后.
	//
	//在每个上述分组内,再根据节点所包含的设备数量进行排序.
	sort.Slice(nodes, func(i, j int) bool {
		// If one or the other of nodes[i] or nodes[j] is in the 'hint's affinity set
		if hint.NUMANodeAffinity.IsSet(nodes[i]) && hint.NUMANodeAffinity.IsSet(nodes[j]) {
			return perNodeDevices[nodes[i]].Len() < perNodeDevices[nodes[j]].Len()
		}
		if hint.NUMANodeAffinity.IsSet(nodes[i]) {
			return true
		}
		if hint.NUMANodeAffinity.IsSet(nodes[j]) {
			return false
		}

		// If one or the other of nodes[i] or nodes[j] is the fake NUMA node -1 (they can't both be)
		if nodes[i] == nodeWithoutTopology {
			return false
		}
		if nodes[j] == nodeWithoutTopology {
			return true
		}

		// Otherwise both nodes[i] and nodes[j] are real NUMA nodes that are not in the 'hint's' affinity list.
		return perNodeDevices[nodes[i]].Len() < perNodeDevices[nodes[j]].Len()
	})

	// 这段代码的作用是生成三个已排序的设备列表.其中,
	// 第一个列表中的设备来自于亲和性掩码中包含的有效NUMA节点.
	// 第二个列表中的设备来自于亲和性掩码中不包含的有效NUMA节点.
	// 第三个列表中的设备来自于没有与任何NUMA节点关联的设备（即映射到虚拟NUMA节点-1的设备）.
	// 由于我们按顺序遍历已排序的NUMA节点列表,在每个列表中,设备按其与具有更多设备的NUMA节点的连接进行排序.
	var fromAffinity []string
	var notFromAffinity []string
	var withoutTopology []string
	for d := range available {
		// Since the same device may be associated with multiple NUMA Nodes. We
		// need to be careful not to add each device to multiple lists. The
		// logic below ensures this by breaking after the first NUMA node that
		// has the device is encountered.
		for _, n := range nodes {
			if perNodeDevices[n].Has(d) {
				if n == nodeWithoutTopology {
					withoutTopology = append(withoutTopology, d)
				} else if hint.NUMANodeAffinity.IsSet(n) {
					fromAffinity = append(fromAffinity, d)
				} else {
					notFromAffinity = append(notFromAffinity, d)
				}
				break
			}
		}
	}

	// Return all three lists containing the full set of devices across them.
	// pod填写了对应的node序号, 根据每个node绑定的设备拓扑 进行分组
	return sets.NewString(fromAffinity...), sets.NewString(notFromAffinity...), sets.NewString(withoutTopology...)
}

// 确定是否需要通过Allocate rpc调用来分配设备资源.
// 如果需要分配设备资源,则返回需要分配的设备ID列表.
// 如果不需要分配设备资源,则返回空列表,表示不需要发出Allocate rpc调用.
// 这可以用于优化资源分配的效率,避免不必要的Allocate rpc调用.
func (m *ManagerImpl) devicesToAllocate(podUID, containerName, resource string, required int, reusableDevices sets.String) (sets.String, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	needed := required
	//获取已经分配的设备列表.
	//如果容器重新启动,就会发生这种情况.
	devices := m.podDevices.containerDevices(podUID, containerName, resource) // 同一种资源可能有多个设备  p4
	if devices != nil {
		klog.V(3).InfoS("Found pre-allocated devices for resource on pod", "resourceName", resource, "containerName", containerName, "podUID", string(podUID), "devices", devices.List())
		needed = needed - devices.Len()
		// 在API服务器接受Pod后,不希望Pod的资源发生更改.如果发生了更改,代码会直接失败并抛出错误.这是基于一个假设,即一旦Pod被接受,其资源应该是不可更改的.如果这个假设不再成立,可能需要重新审视代码的这部分逻辑.
		if needed != 0 {
			return nil, fmt.Errorf("pod %q container %q changed request for resource %q from %d to %d", string(podUID), containerName, resource, devices.Len(), required)
		}
	}
	if needed == 0 {
		// No change, no work.
		return nil, nil
	}
	klog.V(3).InfoS("需要为pod分配设备", "deviceNumber", needed, "resourceName", resource, "podUID", string(podUID), "containerName", containerName)
	// Check if resource registered with devicemanager
	if _, ok := m.healthyDevices[resource]; !ok {
		return nil, fmt.Errorf("无法分配未注册的设备 %s", resource)
	}
	// 已分配的设备列表
	allocated := sets.NewString()

	allocateRemainingFrom := func(devices sets.String) bool {
		//在不再需要分配设备时返回true.这个闭包函数可能会用于在设备分配过程中判断是否还需要继续分配设备.
		for device := range devices.Difference(allocated) { // devices-allocated
			m.allocatedDevices[resource].Insert(device)
			allocated.Insert(device)
			needed--
			if needed == 0 {
				return true
			}
		}
		return false
	}

	// Needs to allocate additional devices.
	if m.allocatedDevices[resource] == nil {
		m.allocatedDevices[resource] = sets.NewString()
	}

	// Allocates from reusableDevices list first.container
	// 判断上一次申请的,是不是恰好够这一次使用
	if allocateRemainingFrom(reusableDevices) {
		return allocated, nil
	}

	// Gets Devices in use.
	// 已经在使用的
	devicesInUse := m.allocatedDevices[resource] // 已经使用的设备
	// Gets Available devices.
	// 剩余可用d
	available := m.healthyDevices[resource].Difference(devicesInUse) // 健康的,没有在使用的资源
	if available.Len() < needed {                                    // 还需要申请的
		return nil, fmt.Errorf("请求的设备数量不可用 for %s. Requested: %d, Available: %d", resource, needed, available.Len())
	}

	// 根据NUMA亲和性进行设备筛选的操作.在设备分配过程中,可能会根据NUMA节点的亲和性来选择合适的设备.
	// 通过筛选可用的设备,可以确保将设备分配给与容器或任务具有相同NUMA节点亲和性的节点,以提高性能和效率.
	// 没有在使用的资源
	aligned, unaligned, noAffinity := m.filterByAffinity(podUID, containerName, resource, available)

	if needed < aligned.Len() { // 从对齐的设备集合中分配所有剩余的设备
		// 首先从首选设备列表中分配（如果有的话）
		preferred, err := m.callGetPreferredAllocationIfAvailable(podUID, containerName, resource, aligned.Union(allocated), allocated, required)
		if err != nil {
			return nil, err
		}
		if allocateRemainingFrom(preferred.Intersection(aligned)) { // 使用优先设备
			return allocated, nil
		}
		// Then fallback to allocate from the aligned set if no preferred list
		// is returned (or not enough devices are returned in that list).
		if allocateRemainingFrom(aligned) {
			return allocated, nil
		}

		return nil, fmt.Errorf("意外地分配的资源少于所需的数量. Requested: %d, Got: %d", required, required-needed)
	}

	//那么首先分配所有对齐的设备（以确保 TopologyManager 所保证的对齐性得到遵守）.
	if allocateRemainingFrom(aligned) {
		return allocated, nil
	}

	// 首选设备
	preferred, err := m.callGetPreferredAllocationIfAvailable(podUID, containerName, resource, available.Union(allocated), allocated, required)
	if err != nil {
		return nil, err
	}
	if allocateRemainingFrom(preferred.Intersection(available)) {
		return allocated, nil
	}

	// 如果插件没有返回首选的分配（或者返回的分配不够大）,那么就从“unaligned”和“noAffinity”集合中分配剩余的设备.
	if allocateRemainingFrom(unaligned) {
		return allocated, nil
	}
	if allocateRemainingFrom(noAffinity) {
		return allocated, nil
	}

	return nil, fmt.Errorf("意外地分配的资源比所需的资源少.. Requested: %d, Got: %d", required, required-needed)
}

// allocateContainerResources 尝试为 容器分配所有所需的设备插件资源,为每个新的设备资源需求发出一个allocate rpc请求,处理它们的 allocater responses,并在成功时更新缓存的containerDevices.
func (m *ManagerImpl) allocateContainerResources(pod *v1.Pod, container *v1.Container, devicesToReuse map[string]sets.String) error {
	podUID := string(pod.UID)
	contName := container.Name
	allocatedDevicesUpdated := false
	needsUpdateCheckpoint := false
	// 确保在资源调度过程中,扩展资源的使用不会超过其限制.它假设设备插件会提供有关扩展资源的信息,包括请求(Requests)和限制(Limits).
	// 通过迭代限制列表,可以检查每个扩展资源的请求和限制是否相等,以确保资源的正确分配和使用.
	for k, v := range container.Resources.Limits {
		resource := string(k)
		needed := int(v.Value())
		klog.V(3).InfoS("Looking for needed resources", "needed", needed, "resourceName", resource)
		if !m.isDevicePluginResource(resource) {
			continue
		}
		// 只在第一次更新allocatedDevices, 以便在进行设备插件分配之前对任何搁浅的资源进行垃圾收集.
		if !allocatedDevicesUpdated {
			m.UpdateAllocatedDevices() // ✅
			allocatedDevicesUpdated = true
		}
		// 设备插件返回的符合亲和性需要的设备列表,没有真的 分配
		allocDevices, err := m.devicesToAllocate(podUID, contName, resource, needed, devicesToReuse[resource])
		if err != nil {
			return err
		}
		// 不需要分配资源
		if allocDevices == nil || len(allocDevices) <= 0 {
			continue
		}

		needsUpdateCheckpoint = true

		startRPCTime := time.Now()
		// Manager.Allocate involves RPC calls to device plugin, which
		// could be heavy-weight. Therefore we want to perform this operation outside
		// mutex lock. Note if Allocate call fails, we may leave container resources
		// partially allocated for the failed container. We rely on UpdateAllocatedDevices()
		// to garbage collect these resources later. Another side effect is that if
		// we have X resource A and Y resource B in total, and two containers, container1
		// and container2 both require X resource A and Y resource B. Both allocation
		// requests may fail if we serve them in mixed order.
		// TODO: may revisit this part later if we see inefficient resource allocation
		// in real use as the result of this. Should also consider to parallelize device
		// plugin Allocate grpc calls if it becomes common that a container may require
		// resources from multiple device plugins.
		m.mutex.Lock()
		eI, ok := m.endpoints[resource]
		m.mutex.Unlock()
		if !ok {
			m.mutex.Lock()
			m.allocatedDevices = m.podDevices.devices()
			m.mutex.Unlock()
			return fmt.Errorf("unknown Device Plugin %s", resource)
		}

		devs := allocDevices.UnsortedList()
		// TODO: refactor this part of code to just append a ContainerAllocationRequest
		// in a passed in AllocateRequest pointer, and issues a single Allocate call per pod.
		klog.V(3).InfoS("Making allocation request for device plugin", "devices", devs, "resourceName", resource)
		resp, err := eI.e.allocate(devs)
		metrics.DevicePluginAllocationDuration.WithLabelValues(resource).Observe(metrics.SinceInSeconds(startRPCTime))
		if err != nil {
			// In case of allocation failure, we want to restore m.allocatedDevices
			// to the actual allocated state from m.podDevices.
			m.mutex.Lock()
			m.allocatedDevices = m.podDevices.devices()
			m.mutex.Unlock()
			return err
		}

		if len(resp.ContainerResponses) == 0 {
			return fmt.Errorf("分配响应中没有返回容器 %v", resp)
		}

		allocDevicesWithNUMA := checkpoint.NewDevicesPerNUMA()
		// Update internal cached podDevices state.
		m.mutex.Lock()
		for dev := range allocDevices {
			if m.allDevices[resource][dev].Topology == nil || len(m.allDevices[resource][dev].Topology.Nodes) == 0 {
				allocDevicesWithNUMA[nodeWithoutTopology] = append(allocDevicesWithNUMA[nodeWithoutTopology], dev)
				continue
			}
			for idx := range m.allDevices[resource][dev].Topology.Nodes {
				node := m.allDevices[resource][dev].Topology.Nodes[idx]
				allocDevicesWithNUMA[node.ID] = append(allocDevicesWithNUMA[node.ID], dev)
			}
		}
		m.mutex.Unlock()
		m.podDevices.insert(podUID, contName, resource, allocDevicesWithNUMA, resp.ContainerResponses[0])
	}

	if needsUpdateCheckpoint {
		return m.writeCheckpoint()
	}

	return nil
}

// Checkpoints device to container allocation information to disk.
func (m *ManagerImpl) writeCheckpoint() error {
	m.mutex.Lock()
	registeredDevs := make(map[string][]string)
	for resource, devices := range m.healthyDevices {
		registeredDevs[resource] = devices.UnsortedList()
	}
	data := checkpoint.New(m.podDevices.toCheckpointData(), registeredDevs)
	m.mutex.Unlock()
	err := m.checkpointManager.CreateCheckpoint(kubeletDeviceManagerCheckpoint, data)
	if err != nil {
		err2 := fmt.Errorf("failed to write checkpoint file %q: %v", kubeletDeviceManagerCheckpoint, err)
		klog.InfoS("Failed to write checkpoint file", "err", err)
		return err2
	}
	return nil
}

func (m *ManagerImpl) getCheckpointV2() (checkpoint.DeviceManagerCheckpoint, error) {
	registeredDevs := make(map[string][]string)
	devEntries := make([]checkpoint.PodDevicesEntry, 0)
	cp := checkpoint.New(devEntries, registeredDevs)
	err := m.checkpointManager.GetCheckpoint(kubeletDeviceManagerCheckpoint, cp)
	return cp, err
}

func (m *ManagerImpl) getCheckpointV1() (checkpoint.DeviceManagerCheckpoint, error) {
	registeredDevs := make(map[string][]string)
	devEntries := make([]checkpoint.PodDevicesEntryV1, 0)
	cp := checkpoint.NewV1(devEntries, registeredDevs)
	err := m.checkpointManager.GetCheckpoint(kubeletDeviceManagerCheckpoint, cp)
	return cp, err
}

// GetWatcherHandler returns the plugin handler
func (m *ManagerImpl) GetWatcherHandler() cache.PluginHandler {
	return m.server
}

// checkpointFile returns device plugin checkpoint file path.
func (m *ManagerImpl) checkpointFile() string {
	return filepath.Join(m.checkpointdir, kubeletDeviceManagerCheckpoint)
}

// Reads device to container allocation information from disk, and populates
// m.allocatedDevices accordingly.
func (m *ManagerImpl) readCheckpoint() error {
	// the vast majority of time we restore a compatible checkpoint, so we try
	// the current version first. Trying to restore older format checkpoints is
	// relevant only in the kubelet upgrade flow, which happens once in a
	// (long) while.
	cp, err := m.getCheckpointV2()
	if err != nil {
		if err == errors.ErrCheckpointNotFound {
			// no point in trying anything else
			klog.InfoS("Failed to read data from checkpoint", "checkpoint", kubeletDeviceManagerCheckpoint, "err", err)
			return nil
		}

		var errv1 error
		// one last try: maybe it's a old format checkpoint?
		cp, errv1 = m.getCheckpointV1()
		if errv1 != nil {
			klog.InfoS("Failed to read checkpoint V1 file", "err", errv1)
			// intentionally return the parent error. We expect to restore V1 checkpoints
			// a tiny fraction of time, so what matters most is the current checkpoint read error.
			return err
		}
		klog.InfoS("Read data from a V1 checkpoint", "checkpoint", kubeletDeviceManagerCheckpoint)
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()
	podDevices, registeredDevs := cp.GetDataInLatestFormat()
	m.podDevices.fromCheckpointData(podDevices)
	m.allocatedDevices = m.podDevices.devices()
	for resource := range registeredDevs {

		//在启动过程中,创建一个空的healthyDevices列表,这样资源容量将保持为零,直到相应的设备插件重新注册.
		m.healthyDevices[resource] = sets.NewString()
		m.unhealthyDevices[resource] = sets.NewString()
		m.endpoints[resource] = endpointInfo{e: newStoppedEndpointImpl(resource), opts: nil}
	}
	return nil
}

// ShouldResetExtendedResourceCapacity 根据检查点文件的可用性,返回扩展资源是否应该重置.检查点文件的缺失强烈表明节点已被重新创建.
func (m *ManagerImpl) ShouldResetExtendedResourceCapacity() bool { // 节点注册、更新时调用
	checkpoints, err := m.checkpointManager.ListCheckpoints()
	if err != nil {
		return false
	}
	return len(checkpoints) == 0
}

// checkPodActive checks if the given pod is still in activePods list
func (m *ManagerImpl) checkPodActive(pod *v1.Pod) bool {
	activePods := m.activePods()
	for _, activePod := range activePods {
		if activePod.UID == pod.UID {
			return true
		}
	}

	return false
}

func (s *sourcesReadyStub) AddSource(source string) {}

func (s *sourcesReadyStub) AllReady() bool { return true }

// CleanupPluginDirectory is to remove all existing unix sockets
// from /var/lib/kubelet/device-plugins on Device Plugin Manager start
func (m *ManagerImpl) CleanupPluginDirectory(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return err
	}
	var errs []error
	for _, name := range names {
		filePath := filepath.Join(dir, name)
		if filePath == m.checkpointFile() {
			continue
		}
		// TODO: Until the bug - https://github.com/golang/go/issues/33357 is fixed, os.stat wouldn't return the
		// right mode(socket) on windows. Hence deleting the file, without checking whether
		// its a socket, on windows.
		stat, err := os.Lstat(filePath)
		if err != nil {
			klog.ErrorS(err, "Failed to stat file", "path", filePath)
			continue
		}
		if stat.IsDir() {
			continue
		}
		err = os.RemoveAll(filePath)
		if err != nil {
			errs = append(errs, err)
			klog.ErrorS(err, "Failed to remove file", "path", filePath)
			continue
		}
	}
	return errorsutil.NewAggregate(errs)
}

// Stop is the function that can stop the plugin server.
// Can be called concurrently, more than once, and is safe to call
// without a prior Start.
func (m *ManagerImpl) Stop() error {
	return m.server.Stop()
}

// Start starts the Device Plugin Manager and start initialization of
// podDevices and allocatedDevices information from checkpointed state and
// starts device plugin registration service.
func (m *ManagerImpl) Start(activePods ActivePodsFunc, sourcesReady config.SourcesReady) error {
	klog.V(2).InfoS("Starting Device Plugin manager")

	m.activePods = activePods
	m.sourcesReady = sourcesReady

	// Loads in allocatedDevices information from disk.
	err := m.readCheckpoint()
	if err != nil {
		klog.InfoS("在无法读取检查点文件后继续执行.设备分配信息可能不是最新的.", "err", err)
	}

	return m.server.Start()
}

func (m *ManagerImpl) markResourceUnhealthy(resourceName string) {
	klog.V(2).InfoS("Mark all resources Unhealthy for resource", "resourceName", resourceName)
	healthyDevices := sets.NewString()
	if _, ok := m.healthyDevices[resourceName]; ok {
		healthyDevices = m.healthyDevices[resourceName]
		m.healthyDevices[resourceName] = sets.NewString()
	}
	if _, ok := m.unhealthyDevices[resourceName]; !ok {
		m.unhealthyDevices[resourceName] = sets.NewString()
	}
	m.unhealthyDevices[resourceName] = m.unhealthyDevices[resourceName].Union(healthyDevices)
}

// PluginConnected 将插件连接到一个新的端点.这是作为设备插件注册的一部分来完成的.
func (m *ManagerImpl) PluginConnected(resourceName string, p plugin.DevicePlugin) error {
	options, err := p.API().GetDevicePluginOptions(context.Background(), &pluginapi.Empty{})
	if err != nil {
		return fmt.Errorf("failed to get device plugin options: %v", err)
	}

	e := newEndpointImpl(p)

	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.endpoints[resourceName] = endpointInfo{e, options}

	return nil
}

// PluginDisconnected is to disconnect a plugin from an endpoint.
// This is done as part of device plugin deregistration.
// 用于从端点断开插件的连接.这是作为设备插件注销的一部分来完成的.
func (m *ManagerImpl) PluginDisconnected(resourceName string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.endpoints[resourceName]; exists {
		m.markResourceUnhealthy(resourceName)
		klog.V(2).InfoS("Endpoint became unhealthy", "resourceName", resourceName, "endpoint", m.endpoints[resourceName])
	}

	m.endpoints[resourceName].e.setStopTime(time.Now())
}

// PluginListAndWatchReceiver receives ListAndWatchResponse from a device plugin
// and ensures that an upto date state (e.g. number of devices and device health)
// is captured. Also, registered device and device to container allocation
// information is checkpointed to the disk.
// 接收来自设备插件的ListAndWatchResponse,并确保捕获最新的状态（例如设备数量和设备健康状况）.
// 此外,注册的设备和设备到容器的分配信息将被检查点到磁盘上.
func (m *ManagerImpl) PluginListAndWatchReceiver(resourceName string, resp *pluginapi.ListAndWatchResponse) {
	var devices []pluginapi.Device
	for _, d := range resp.Devices {
		devices = append(devices, *d)
	}
	m.genericDeviceUpdateCallback(resourceName, devices)
}

func (m *ManagerImpl) genericDeviceUpdateCallback(resourceName string, devices []pluginapi.Device) {
	m.mutex.Lock()
	m.healthyDevices[resourceName] = sets.NewString()
	m.unhealthyDevices[resourceName] = sets.NewString()
	m.allDevices[resourceName] = make(map[string]pluginapi.Device)
	for _, dev := range devices {
		m.allDevices[resourceName][dev.ID] = dev
		if dev.Health == pluginapi.Healthy {
			m.healthyDevices[resourceName].Insert(dev.ID)
		} else {
			m.unhealthyDevices[resourceName].Insert(dev.ID)
		}
	}
	m.mutex.Unlock()
	if err := m.writeCheckpoint(); err != nil {
		klog.ErrorS(err, "Writing checkpoint encountered")
	}
}
