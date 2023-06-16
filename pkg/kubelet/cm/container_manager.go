/*
Copyright 2015 The Kubernetes Authors.

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

package cm

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	// TODO: Migrate kubelet to either use its own internal objects or client library.
	v1 "k8s.io/api/core/v1"
	internalapi "k8s.io/cri-api/pkg/apis"
	podresourcesapi "k8s.io/kubelet/pkg/apis/podresources/v1"
	kubeletconfig "k8s.io/kubernetes/pkg/kubelet/apis/config"
	"k8s.io/kubernetes/pkg/kubelet/apis/podresources"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpuset"
	"k8s.io/kubernetes/pkg/kubelet/cm/devicemanager"
	"k8s.io/kubernetes/pkg/kubelet/cm/dra"
	"k8s.io/kubernetes/pkg/kubelet/config"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	evictionapi "k8s.io/kubernetes/pkg/kubelet/eviction/api"
	"k8s.io/kubernetes/pkg/kubelet/lifecycle"
	"k8s.io/kubernetes/pkg/kubelet/pluginmanager/cache"
	"k8s.io/kubernetes/pkg/kubelet/status"
	schedulerframework "k8s.io/kubernetes/pkg/scheduler/framework"
)

type ActivePodsFunc func() []*v1.Pod

// ContainerManager -  管理容器的各种资源,比如 CGroups、QoS、cpuset、device 等
// - 内置了很多资源管理器,总结起来就是其他manager的管家
type ContainerManager interface {
	// Start 运行容器管理器的 housekeeping.
	// - 确保 Docker 守护进程在容器中运行.
	// - 创建系统容器,其中运行所有非容器化进程.
	Start(*v1.Node, ActivePodsFunc, config.SourcesReady, status.PodStatusProvider, internalapi.RuntimeService, bool) error

	// SystemCgroupsLimit returns resources allocated to system cgroups in the machine.
	// These cgroups include the system and Kubernetes services.
	SystemCgroupsLimit() v1.ResourceMap

	GetNodeConfig() NodeConfig                                                   // 返回节点配置
	Status() Status                                                              // 返回内部错误信息
	NewPodContainerManager() PodContainerManager                                 // 工厂函数返回podContainerManager对象
	GetMountedSubsystems() *CgroupSubsystems                                     // 返回节点上挂载的 cgroup subsystems
	GetQOSContainersInfo() QOSContainersInfo                                     //  返回顶级qos 容器名
	GetNodeAllocatableReservation() v1.ResourceMap                               // 返回节点预留的资源
	GetCapacity(localStorageCapacityIsolation bool) v1.ResourceMap               //  返回节点上可用的资源
	GetDevicePluginResourceCapacity() (v1.ResourceMap, v1.ResourceMap, []string) // 返回节点上插件资源总量,可用总量和不活跃的插件资源
	UpdateQOSCgroups() error                                                     // 确保顶级qos容器在期望的状态中

	// GetResources returns RunContainerOptions with devices, mounts, and env fields populated for
	// extended resources required by container.
	GetResources(pod *v1.Pod, container *v1.Container) (*kubecontainer.RunContainerOptions, error) // 返回
	UpdatePluginResources(*schedulerframework.NodeInfo, *lifecycle.PodAdmitAttributes) error       // 预分配需要的资源
	InternalContainerLifecycle() InternalContainerLifecycle                                        //
	GetPodCgroupRoot() string                                                                      // 返回 cgroup的root
	GetPluginRegistrationHandler() cache.PluginHandler                                             // 插件注册

	ShouldResetExtendedResourceCapacity() bool                      // 决定扩展资源是否清理
	GetAllocateResourcesPodAdmitHandler() lifecycle.PodAdmitHandler // pod资源准入控制器
	// GetNodeAllocatableAbsolute returns the absolute value of Node Allocatable which is primarily useful for enforcement.
	GetNodeAllocatableAbsolute() v1.ResourceMap

	// PrepareResource prepares pod resources
	PrepareResources(pod *v1.Pod, container *v1.Container) (*dra.ContainerInfo, error)

	// UnrepareResources unprepares pod resources
	UnprepareResources(*v1.Pod) error
	PodMightNeedToUnprepareResources(UID types.UID) bool // 如果具有给定UID的pod可能需要准备资源,则返回true.

	// Implements the podresources Provider API for CPUs, Memory and Devices
	podresources.CPUsProvider
	podresources.DevicesProvider
	podresources.MemoryProvider
}

type NodeConfig struct {
	RuntimeCgroupsName    string
	SystemCgroupsName     string
	KubeletCgroupsName    string
	KubeletOOMScoreAdj    int32
	ContainerRuntime      string
	CgroupsPerQOS         bool   // ✅
	CgroupRoot            string // ✅
	CgroupDriver          string // ✅
	KubeletRootDir        string
	ProtectKernelDefaults bool
	NodeAllocatableConfig
	QOSReserved                              map[v1.ResourceName]int64
	CPUManagerPolicy                         string
	CPUManagerPolicyOptions                  map[string]string
	CPUManagerReconcilePeriod                time.Duration
	ExperimentalMemoryManagerPolicy          string
	ExperimentalMemoryManagerReservedMemory  []kubeletconfig.MemoryReservation
	ExperimentalPodPidsLimit                 int64 // 进程数限制
	EnforceCPULimits                         bool
	CPUCFSQuotaPeriod                        time.Duration
	ExperimentalTopologyManagerScope         string            // ✅
	ExperimentalTopologyManagerPolicy        string            // ✅
	ExperimentalTopologyManagerPolicyOptions map[string]string // ✅
}

// NodeAllocatableConfig 存储节点可分配资源的配置信息
type NodeAllocatableConfig struct {
	KubeReservedCgroupName   string                  // 表示用于限制 Kubernetes 系统保留资源的 Cgroup 名称.
	SystemReservedCgroupName string                  // 表示用于限制系统保留资源的 Cgroup 名称.
	ReservedSystemCPUs       cpuset.CPUSet           // 保留给系统使用的 CPU 集合.
	EnforceNodeAllocatable   sets.String             // 表示是否强制使用节点可分配资源.
	KubeReserved             v1.ResourceMap          // 表示 Kubernetes 系统保留资源的数量.
	SystemReserved           v1.ResourceMap          // 表示系统保留资源的数量.
	HardEvictionThresholds   []evictionapi.Threshold // 表示硬驱逐阈值列表.
}

type Status struct {
	SoftRequirements error // 任何未被满足的软需求
}

// parsePercentage parses the percentage string to numeric value.
func parsePercentage(v string) (int64, error) {
	if !strings.HasSuffix(v, "%") {
		return 0, fmt.Errorf("percentage expected, got '%s'", v)
	}
	percentage, err := strconv.ParseInt(strings.TrimRight(v, "%"), 10, 0)
	if err != nil {
		return 0, fmt.Errorf("invalid number in percentage '%s'", v)
	}
	if percentage < 0 || percentage > 100 {
		return 0, fmt.Errorf("percentage must be between 0 and 100")
	}
	return percentage, nil
}

// ParseQOSReserved parses the --qos-reserve-requests option
func ParseQOSReserved(m map[string]string) (*map[v1.ResourceName]int64, error) {
	reservations := make(map[v1.ResourceName]int64)
	for k, v := range m {
		switch v1.ResourceName(k) {
		// Only memory resources are supported.
		case v1.ResourceMemory:
			q, err := parsePercentage(v)
			if err != nil {
				return nil, err
			}
			reservations[v1.ResourceName(k)] = q
		default:
			return nil, fmt.Errorf("cannot reserve %q resource", k)
		}
	}
	return &reservations, nil
}

func containerDevicesFromResourceDeviceInstances(devs devicemanager.ResourceDeviceInstances) []*podresourcesapi.ContainerDevices {
	var respDevs []*podresourcesapi.ContainerDevices

	for resourceName, resourceDevs := range devs {
		for devID, dev := range resourceDevs {
			topo := dev.GetTopology()
			if topo == nil {
				// Some device plugin do not report the topology information.
				// This is legal, so we report the devices anyway,
				// let the client decide what to do.
				respDevs = append(respDevs, &podresourcesapi.ContainerDevices{
					ResourceName: resourceName,
					DeviceIds:    []string{devID},
				})
				continue
			}

			for _, node := range topo.GetNodes() {
				respDevs = append(respDevs, &podresourcesapi.ContainerDevices{
					ResourceName: resourceName,
					DeviceIds:    []string{devID},
					Topology: &podresourcesapi.TopologyInfo{
						Nodes: []*podresourcesapi.NUMANode{
							{
								ID: node.GetID(),
							},
						},
					},
				})
			}
		}
	}

	return respDevs
}
