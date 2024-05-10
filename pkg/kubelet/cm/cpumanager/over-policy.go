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

package cpumanager

import (
	"k8s.io/api/core/v1"

	"k8s.io/kubernetes/pkg/kubelet/cm/cpumanager/state"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpuset"
	"k8s.io/kubernetes/pkg/kubelet/cm/topologymanager"
)

// Policy implements logic for pod container to CPU assignment.
type Policy interface {
	Name() string
	Start(s state.State) error
	Allocate(s state.State, pod *v1.Pod, container *v1.Container) error
	RemoveContainer(s state.State, podUID string, containerName string) error
	GetTopologyHints(s state.State, pod *v1.Pod, container *v1.Container) map[string][]topologymanager.TopologyHint
	GetPodTopologyHints(s state.State, pod *v1.Pod) map[string][]topologymanager.TopologyHint // 该函数返回可供分配的 CPU 总数的集合.
	GetAllocatableCPUs(m state.State) cpuset.CPUSet                                           // 该函数返回可供分配的 CPU 总数的集合.
}
