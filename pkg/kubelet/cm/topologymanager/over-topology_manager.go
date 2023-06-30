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

package topologymanager

import (
	"fmt"

	cadvisorapi "github.com/google/cadvisor/info/v1"
	"k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/kubelet/cm/topologymanager/bitmask"
	"k8s.io/kubernetes/pkg/kubelet/lifecycle"
)

const (
	maxAllowableNUMANodes = 8 // 最多8个CPU,在处理大量NUMA节点时,生成和管理NUMAAffinity掩码的复杂性会显著增加,可能导致性能下降或系统不稳定.
	ErrorTopologyAffinity = "TopologyAffinityError"
)

// TopologyAffinityError represents an resource alignment error
type TopologyAffinityError struct{}

func (e TopologyAffinityError) Error() string {
	return "Resources cannot be allocated with Topology locality"
}

func (e TopologyAffinityError) Type() string {
	return ErrorTopologyAffinity
}

// Manager 用于管理节点的拓扑结构信息,用来优化容器中应用在高性能服务器上的性能
type Manager interface {
	// PodAdmitHandler is implemented by Manager
	lifecycle.PodAdmitHandler
	// AddHintProvider adds a hint provider to ScopeManager to indicate the hint provider
	// wants to be consulted with when making topology hints
	AddHintProvider(HintProvider) // 向ScopeManager添加一个程序,以指示在创建拓扑提示时要咨询的提示提供程序
	// AddContainer adds pod to Manager for tracking
	AddContainer(pod *v1.Pod, container *v1.Container, containerID string) // 从manager 跟踪中添加pod
	RemoveContainer(containerID string) error                              // 从manager 跟踪中移除pod
	Store                                                                  // 存储pod拓扑提示
}

type ScopeManager struct {
	Scope Scope // 拓扑管理器范围
}

// HintProvider 是一个接口,用于希望协作以实现全局最优具体资源对齐的组件.
type HintProvider interface {
	GetTopologyHints(pod *v1.Pod, container *v1.Container) map[string][]TopologyHint // 根据NUMA位置提示将资源名映射返回到可能的具体资源分配列表.
	GetPodTopologyHints(pod *v1.Pod) map[string][]TopologyHint                       // 根据NUMA位置提示将资源名映射返回到可能的具体资源分配列表.  (所有container 资源加起来)
	Allocate(pod *v1.Pod, container *v1.Container) error                             // 资源分配
}

// Store interface is to allow Hint Providers to retrieve pod affinity
type Store interface {
	GetAffinity(podUID string, containerName string) TopologyHint
	GetPolicy() Policy
}

type TopologyHint struct {
	NUMANodeAffinity bitmask.BitMask
	Preferred        bool // 当NUMANodeAffinity编码了对容器的首选分配时,Preferred被设置为true.否则,设置为false.
}

// IsEqual checks if TopologyHint are equal
func (th *TopologyHint) IsEqual(topologyHint TopologyHint) bool {
	if th.Preferred == topologyHint.Preferred {
		if th.NUMANodeAffinity == nil || topologyHint.NUMANodeAffinity == nil {
			return th.NUMANodeAffinity == topologyHint.NUMANodeAffinity
		}
		return th.NUMANodeAffinity.IsEqual(topologyHint.NUMANodeAffinity)
	}
	return false
}

// LessThan checks if TopologyHint `a` is less than TopologyHint `b`
// this means that either `a` is a preferred hint and `b` is not
// or `a` NUMANodeAffinity attribute is narrower than `b` NUMANodeAffinity attribute.
func (th *TopologyHint) LessThan(other TopologyHint) bool {
	if th.Preferred != other.Preferred {
		return th.Preferred
	}
	return th.NUMANodeAffinity.IsNarrowerThan(other.NUMANodeAffinity)
}

func (m *ScopeManager) Admit(attrs *lifecycle.PodAdmitAttributes) lifecycle.PodAdmitResult {
	klog.InfoS("Topology Admit Handler")
	pod := attrs.Pod

	return m.Scope.Admit(pod)
}
func NewManager(topology []cadvisorapi.Node, topologyPolicyName string, topologyScopeName string, topologyPolicyOptions map[string]string) (Manager, error) {
	klog.InfoS("Creating topology ScopeManager with policy per Scope", "topologyPolicyName", topologyPolicyName, "topologyScopeName", topologyScopeName)

	opts, err := NewPolicyOptions(topologyPolicyOptions) // ✅
	if err != nil {
		return nil, err
	}

	numaInfo, err := NewNUMAInfo(topology, opts) // ✅
	if err != nil {
		return nil, fmt.Errorf("cannot discover NUMA topology: %w", err)
	}

	if topologyPolicyName != PolicyNone && len(numaInfo.Nodes) > maxAllowableNUMANodes {
		return nil, fmt.Errorf("unsupported on machines with more than %v NUMA Nodes", maxAllowableNUMANodes)
	}

	var policy Policy
	switch topologyPolicyName {

	case PolicyNone:
		policy = NewNonePolicy()
		var _ = new(nonePolicy).Merge // ✅
	case PolicyBestEffort:
		policy = NewBestEffortPolicy(numaInfo, opts)
		var _ = new(bestEffortPolicy).Merge
	case PolicyRestricted:
		policy = NewRestrictedPolicy(numaInfo, opts)
		var _ = new(restrictedPolicy).Merge
	case PolicySingleNumaNode:
		policy = NewSingleNumaNodePolicy(numaInfo, opts)
		var _ = new(singleNumaNodePolicy).Merge
	default:
		return nil, fmt.Errorf("unknown policy: \"%s\"", topologyPolicyName)
	}

	var scope Scope
	switch topologyScopeName {
	case containerTopologyScope:
		scope = NewContainerScope(policy)
		var _ = new(ContainerScope).Admit // ✅
	case podTopologyScope:
		scope = NewPodScope(policy)
		var _ = new(PodScope).Admit // ✅
	default:
		return nil, fmt.Errorf("unknown Scope: \"%s\"", topologyScopeName)
	}

	manager := &ScopeManager{
		Scope: scope,
	}

	return manager, nil
}

var _ Manager = &ScopeManager{}

func (m *ScopeManager) GetAffinity(podUID string, containerName string) TopologyHint {
	return m.Scope.GetAffinity(podUID, containerName)
}

func (m *ScopeManager) GetPolicy() Policy {
	return m.Scope.GetPolicy()
}

func (m *ScopeManager) AddHintProvider(h HintProvider) {
	m.Scope.AddHintProvider(h)
}

func (m *ScopeManager) AddContainer(pod *v1.Pod, container *v1.Container, containerID string) {
	m.Scope.AddContainer(pod, container, containerID)
}

func (m *ScopeManager) RemoveContainer(containerID string) error {
	return m.Scope.RemoveContainer(containerID)
}
