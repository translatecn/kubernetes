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
	"fmt"

	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	v1qos "k8s.io/kubernetes/pkg/apis/core/v1/helper/qos"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpumanager/state"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpumanager/topology"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpuset"
	"k8s.io/kubernetes/pkg/kubelet/cm/topologymanager"
	"k8s.io/kubernetes/pkg/kubelet/cm/topologymanager/bitmask"
	"k8s.io/kubernetes/pkg/kubelet/metrics"
)

const (
	PolicyStatic      policyName = "static"            // 静态 CPU 分配策略的名称
	ErrorSMTAlignment            = "SMTAlignmentError" // SMT 对齐错误的类型.
)

// SMTAlignmentError represents an error due to SMT alignment
type SMTAlignmentError struct {
	RequestedCPUs int
	CpusPerCore   int
}

func (e SMTAlignmentError) Error() string {
	return fmt.Sprintf("SMT Alignment Error: requested %d cpus not multiple cpus per core = %d", e.RequestedCPUs, e.CpusPerCore)
}

// Type returns human-readable type of this error. Used in the admission control to populate Admission Failure reason.
func (e SMTAlignmentError) Type() string {
	return ErrorSMTAlignment
}

// StaticPolicy is a CPU CpuManager policy that does not change CPU
// assignments for exclusively pinned guaranteed containers after the main
// container process starts.
//
// This policy allocates CPUs exclusively for a container if all the following
// conditions are met:
//
// - The pod QoS class is Guaranteed.
// - The CPU request is a positive integer.
//
// The static policy maintains the following sets of logical CPUs:
//
//   - SHARED: Burstable, BestEffort, and non-integral Guaranteed containers
//     run here. Initially this contains all CPU IDs on the system. As
//     exclusive allocations are created and destroyed, this CPU set shrinks
//     and grows, accordingly. This is stored in the state as the default
//     CPU set.
//
//   - RESERVED: A subset of the shared pool which is not exclusively
//     allocatable. The membership of this pool is static for the lifetime of
//     the Kubelet. The size of the reserved pool is
//     ceil(systemreserved.cpu + kubereserved.cpu).
//     Reserved CPUs are taken topologically starting with lowest-indexed
//     physical core, as reported by cAdvisor.
//
//   - ASSIGNABLE: Equal to SHARED - RESERVED. Exclusive CPUs are allocated
//     from this pool.
//
//   - EXCLUSIVE ALLOCATIONS: CPU sets assigned exclusively to one container.
//     These are stored as explicit assignments in the state.
//
// When an exclusive allocation is made, the static policy also updates the
// default cpuset in the state abstraction. The CPU CpuManager's periodic
// reconcile loop takes care of rewriting the cpuset in cgroupfs for any
// containers that may be running in the shared pool. For this reason,
// applications running within exclusively-allocated containers must tolerate
// potentially sharing their allocated CPUs for up to the CPU CpuManager
// reconcile period.
type StaticPolicy struct {
	topology    *topology.CPUTopology
	reserved    cpuset.CPUSet            // 一组不能用于独占分配的cpu
	affinity    topologymanager.Store    // 获取容器拓扑关系
	cpusToReuse map[string]cpuset.CPUSet // 在pod中的分配中重用的一组cpu
	options     StaticPolicyOptions      // 允许微调策略的行为
}

// Ensure StaticPolicy implements Policy interface
var _ Policy = &StaticPolicy{}

func (p *StaticPolicy) Name() string {
	return string(PolicyStatic)
}

func (p *StaticPolicy) validateState(s state.State) error {
	tmpAssignments := s.GetCPUAssignments()
	tmpDefaultCPUset := s.GetDefaultCPUSet()

	// Default cpuset cannot be empty when assignments exist
	if tmpDefaultCPUset.IsEmpty() {
		if len(tmpAssignments) != 0 {
			return fmt.Errorf("default cpuset cannot be empty")
		}
		// state is empty initialize
		allCPUs := p.topology.CPUDetails.CPUs()
		s.SetDefaultCPUSet(allCPUs)
		return nil
	}

	// State has already been initialized from file (is not empty)
	// 1. Check if the reserved cpuset is not part of default cpuset because:
	// - kube/system reserved have changed (increased) - may lead to some containers not being able to start
	// - user tampered with file
	if !p.reserved.Intersection(tmpDefaultCPUset).Equals(p.reserved) {
		return fmt.Errorf("not all reserved cpus: \"%s\" are present in defaultCpuSet: \"%s\"",
			p.reserved.String(), tmpDefaultCPUset.String())
	}

	// 2. Check if state for static policy is consistent
	for pod := range tmpAssignments {
		for container, cset := range tmpAssignments[pod] {
			// None of the cpu in DEFAULT cset should be in s.assignments
			if !tmpDefaultCPUset.Intersection(cset).IsEmpty() {
				return fmt.Errorf("pod: %s, container: %s cpuset: \"%s\" overlaps with default cpuset \"%s\"",
					pod, container, cset.String(), tmpDefaultCPUset.String())
			}
		}
	}

	// 3. It's possible that the set of available CPUs has changed since
	// the state was written. This can be due to for example
	// offlining a CPU when kubelet is not running. If this happens,
	// CPU CpuManager will run into trouble when later it tries to
	// assign non-existent CPUs to containers. Validate that the
	// topology that was received during CPU CpuManager startup matches with
	// the set of CPUs stored in the state.
	totalKnownCPUs := tmpDefaultCPUset.Clone()
	tmpCPUSets := []cpuset.CPUSet{}
	for pod := range tmpAssignments {
		for _, cset := range tmpAssignments[pod] {
			tmpCPUSets = append(tmpCPUSets, cset)
		}
	}
	totalKnownCPUs = totalKnownCPUs.UnionAll(tmpCPUSets)
	if !totalKnownCPUs.Equals(p.topology.CPUDetails.CPUs()) {
		return fmt.Errorf("current set of available CPUs \"%s\" doesn't match with CPUs in state \"%s\"",
			p.topology.CPUDetails.CPUs().String(), totalKnownCPUs.String())
	}

	return nil
}

func (p *StaticPolicy) Allocate(s state.State, pod *v1.Pod, container *v1.Container) (rerr error) {
	numCPUs := p.guaranteedCPUs(pod, container)
	if numCPUs == 0 {
		// container belongs in the shared pool (nothing to do; use default cpuset)
		return nil
	}

	klog.InfoS("Static policy: Allocate", "pod", klog.KObj(pod), "containerName", container.Name)
	// container belongs in an exclusively allocated pool
	metrics.CPUManagerPinningRequestsTotal.Inc()
	defer func() {
		if rerr != nil {
			metrics.CPUManagerPinningErrorsTotal.Inc()
		}
	}()

	if p.options.FullPhysicalCPUsOnly && ((numCPUs % p.topology.CPUsPerCore()) != 0) {
		// Since CPU Manager has been enabled requesting strict SMT alignment, it means a guaranteed pod can only be admitted
		// if the CPU requested is a multiple of the number of virtual cpus per physical cores.
		// In case CPU request is not a multiple of the number of virtual cpus per physical cores the Pod will be put
		// in Failed state, with SMTAlignmentError as reason. Since the allocation happens in terms of physical cores
		// and the scheduler is responsible for ensuring that the workload goes to a node that has enough CPUs,
		// the pod would be placed on a node where there are enough physical cores available to be allocated.
		// Just like the behaviour in case of static policy, takeByTopology will try to first allocate CPUs from the same socket
		// and only in case the request cannot be sattisfied on a single socket, CPU allocation is done for a workload to occupy all
		// CPUs on a physical core. Allocation of individual threads would never have to occur.
		return SMTAlignmentError{
			RequestedCPUs: numCPUs,
			CpusPerCore:   p.topology.CPUsPerCore(),
		}
	}
	if cpuset, ok := s.GetCPUSet(string(pod.UID), container.Name); ok {
		p.updateCPUsToReuse(pod, container, cpuset)
		klog.InfoS("Static policy: container already present in state, skipping", "pod", klog.KObj(pod), "containerName", container.Name)
		return nil
	}

	// Call Topology Manager to get the aligned socket affinity across all hint providers.
	hint := p.affinity.GetAffinity(string(pod.UID), container.Name)
	klog.InfoS("Topology Affinity", "pod", klog.KObj(pod), "containerName", container.Name, "affinity", hint)

	// Allocate CPUs according to the NUMA affinity contained in the hint.
	cpuset, err := p.allocateCPUs(s, numCPUs, hint.NUMANodeAffinity, p.cpusToReuse[string(pod.UID)])
	if err != nil {
		klog.ErrorS(err, "Unable to allocate CPUs", "pod", klog.KObj(pod), "containerName", container.Name, "numCPUs", numCPUs)
		return err
	}
	s.SetCPUSet(string(pod.UID), container.Name, cpuset)
	p.updateCPUsToReuse(pod, container, cpuset)

	return nil
}

func (p *StaticPolicy) GetTopologyHints(s state.State, pod *v1.Pod, container *v1.Container) map[string][]topologymanager.TopologyHint {
	// Get a count of how many guaranteed CPUs have been requested.
	requested := p.guaranteedCPUs(pod, container)

	// Number of required CPUs is not an integer or a container is not part of the Guaranteed QoS class.
	// It will be treated by the TopologyManager as having no preference and cause it to ignore this
	// resource when considering pod alignment.
	// In terms of hints, this is equal to: TopologyHints[NUMANodeAffinity: nil, Preferred: true].
	if requested == 0 {
		return nil
	}

	// Short circuit to regenerate the same hints if there are already
	// guaranteed CPUs allocated to the Container. This might happen after a
	// kubelet restart, for example.
	if allocated, exists := s.GetCPUSet(string(pod.UID), container.Name); exists {
		if allocated.Size() != requested {
			klog.ErrorS(nil, "CPUs already allocated to container with different number than request", "pod", klog.KObj(pod), "containerName", container.Name, "requestedSize", requested, "allocatedSize", allocated.Size())
			// An empty list of hints will be treated as a preference that cannot be satisfied.
			// In definition of hints this is equal to: TopologyHint[NUMANodeAffinity: nil, Preferred: false].
			// For all but the best-effort policy, the Topology Manager will throw a pod-admission error.
			return map[string][]topologymanager.TopologyHint{
				string(v1.ResourceCPU): {},
			}
		}
		klog.InfoS("Regenerating TopologyHints for CPUs already allocated", "pod", klog.KObj(pod), "containerName", container.Name)
		return map[string][]topologymanager.TopologyHint{
			string(v1.ResourceCPU): p.generateCPUTopologyHints(allocated, cpuset.CPUSet{}, requested),
		}
	}

	// Get a list of available CPUs.
	available := p.GetAvailableCPUs(s)

	// Get a list of reusable CPUs (e.g. CPUs reused from initContainers).
	// It should be an empty CPUSet for a newly created pod.
	reusable := p.cpusToReuse[string(pod.UID)]

	// Generate hints.
	cpuHints := p.generateCPUTopologyHints(available, reusable, requested)
	klog.InfoS("TopologyHints generated", "pod", klog.KObj(pod), "containerName", container.Name, "cpuHints", cpuHints)

	return map[string][]topologymanager.TopologyHint{
		string(v1.ResourceCPU): cpuHints,
	}
}

func (p *StaticPolicy) GetPodTopologyHints(s state.State, pod *v1.Pod) map[string][]topologymanager.TopologyHint {
	// Get a count of how many guaranteed CPUs have been requested by Pod.
	requested := p.podGuaranteedCPUs(pod)

	// Number of required CPUs is not an integer or a pod is not part of the Guaranteed QoS class.
	// It will be treated by the TopologyManager as having no preference and cause it to ignore this
	// resource when considering pod alignment.
	// In terms of hints, this is equal to: TopologyHints[NUMANodeAffinity: nil, Preferred: true].
	if requested == 0 {
		return nil
	}

	assignedCPUs := cpuset.NewCPUSet()
	for _, container := range append(pod.Spec.InitContainers, pod.Spec.Containers...) {
		requestedByContainer := p.guaranteedCPUs(pod, &container)
		// Short circuit to regenerate the same hints if there are already
		// guaranteed CPUs allocated to the Container. This might happen after a
		// kubelet restart, for example.
		if allocated, exists := s.GetCPUSet(string(pod.UID), container.Name); exists {
			if allocated.Size() != requestedByContainer {
				klog.ErrorS(nil, "CPUs already allocated to container with different number than request", "pod", klog.KObj(pod), "containerName", container.Name, "allocatedSize", requested, "requestedByContainer", requestedByContainer, "allocatedSize", allocated.Size())
				// An empty list of hints will be treated as a preference that cannot be satisfied.
				// In definition of hints this is equal to: TopologyHint[NUMANodeAffinity: nil, Preferred: false].
				// For all but the best-effort policy, the Topology Manager will throw a pod-admission error.
				return map[string][]topologymanager.TopologyHint{
					string(v1.ResourceCPU): {},
				}
			}
			// A set of CPUs already assigned to containers in this pod
			assignedCPUs = assignedCPUs.Union(allocated)
		}
	}
	if assignedCPUs.Size() == requested {
		klog.InfoS("Regenerating TopologyHints for CPUs already allocated", "pod", klog.KObj(pod))
		return map[string][]topologymanager.TopologyHint{
			string(v1.ResourceCPU): p.generateCPUTopologyHints(assignedCPUs, cpuset.CPUSet{}, requested),
		}
	}

	// Get a list of available CPUs.
	available := p.GetAvailableCPUs(s)

	// Get a list of reusable CPUs (e.g. CPUs reused from initContainers).
	// It should be an empty CPUSet for a newly created pod.
	reusable := p.cpusToReuse[string(pod.UID)]

	// Ensure any CPUs already assigned to containers in this pod are included as part of the hint generation.
	reusable = reusable.Union(assignedCPUs)

	// Generate hints.
	cpuHints := p.generateCPUTopologyHints(available, reusable, requested)
	klog.InfoS("TopologyHints generated", "pod", klog.KObj(pod), "cpuHints", cpuHints)

	return map[string][]topologymanager.TopologyHint{
		string(v1.ResourceCPU): cpuHints,
	}
}

func (p *StaticPolicy) generateCPUTopologyHints(availableCPUs cpuset.CPUSet, reusableCPUs cpuset.CPUSet, request int) []topologymanager.TopologyHint {
	// 从众多CPU numa 拓扑中，找到符合 request 需求的 numa 组合
	minAffinitySize := p.topology.CPUDetails.NUMANodes().Size()
	var hints []topologymanager.TopologyHint
	bitmask.IterateBitMasks(p.topology.CPUDetails.NUMANodes().ToSlice(), func(mask bitmask.BitMask) {
		// 首先，更新当前请求大小的minAffinitySize。
		cpusInMask := p.topology.CPUDetails.CPUsInNUMANodes(mask.GetBits()...).Size()
		if cpusInMask >= request && mask.Count() < minAffinitySize {
			minAffinitySize = mask.Count()
		}
		// Then check to see if we have enough CPUs available on the current
		// numa node bitmask to satisfy the CPU request.
		numMatching := 0
		for _, c := range reusableCPUs.ToSlice() {
			// Disregard this mask if its NUMANode isn't part of it.
			if !mask.IsSet(p.topology.CPUDetails[c].NUMANodeID) {
				return
			}
			numMatching++
		}
		//最后，检查当前NUMA节点组合上是否有足够的可用CPU来满足CPU请求。
		for _, c := range availableCPUs.ToSlice() {
			if mask.IsSet(p.topology.CPUDetails[c].NUMANodeID) {
				numMatching++
			}
		}
		// If they don't, then move onto the next combination.
		if numMatching < request {
			return
		}
		// Otherwise, create a new hint from the numa node bitmask and add it to the
		// list of hints.  We set all hint preferences to 'false' on the first
		// pass through.
		hints = append(hints, topologymanager.TopologyHint{
			NUMANodeAffinity: mask,
			Preferred:        false,
		})
	})
	// 循环遍历所有的hits，并根据亲和性掩码中设置的位数进行更新 'Preferred' 字段，
	// 并将其与 minAffinitySize 进行比较。只有那些设置了相同位数的（和最小的NUMA节点集合）将被认为是首选。
	for i := range hints {
		if p.options.AlignBySocket && p.isHintSocketAligned(hints[i], minAffinitySize) {
			hints[i].Preferred = true // cpu
			continue
		}
		if hints[i].NUMANodeAffinity.Count() == minAffinitySize {
			hints[i].Preferred = true // cpu
		}
	}

	return hints
}

// -------------------------------------------------------------------------------------------------------------------

// getAlignedCPUs 根据numa亲和掩码和配置的策略选项返回对齐的cpu集。
func (p *StaticPolicy) getAlignedCPUs(numaAffinity bitmask.BitMask, allocatableCPUs cpuset.CPUSet) cpuset.CPUSet {
	alignedCPUs := cpuset.NewCPUSet()
	numaBits := numaAffinity.GetBits()

	// If align-by-socket policy option is enabled, NUMA based hint is expanded to
	// socket aligned hint. It will ensure that first socket aligned available CPUs are
	// allocated before we try to find CPUs across socket to satisfy allocation request.
	if p.options.AlignBySocket {
		socketBits := p.topology.CPUDetails.SocketsInNUMANodes(numaBits...).ToSliceNoSort()
		for _, socketID := range socketBits {
			alignedCPUs = alignedCPUs.Union(allocatableCPUs.Intersection(p.topology.CPUDetails.CPUsInSockets(socketID)))
		}
		return alignedCPUs
	}

	for _, numaNodeID := range numaBits {
		alignedCPUs = alignedCPUs.Union(allocatableCPUs.Intersection(p.topology.CPUDetails.CPUsInNUMANodes(numaNodeID)))
	}

	return alignedCPUs
}

func (p *StaticPolicy) updateCPUsToReuse(pod *v1.Pod, container *v1.Container, cset cpuset.CPUSet) {
	// If pod entries to m.cpusToReuse other than the current pod exist, delete them.
	for podUID := range p.cpusToReuse {
		if podUID != string(pod.UID) {
			delete(p.cpusToReuse, podUID)
		}
	}
	// If no cpuset exists for cpusToReuse by this pod yet, create one.
	if _, ok := p.cpusToReuse[string(pod.UID)]; !ok {
		p.cpusToReuse[string(pod.UID)] = cpuset.NewCPUSet()
	}
	//检查容器是否为init容器。
	//如果是，将其cpuset添加到任何新分配的可重用cpu的cpuset中。
	for _, initContainer := range pod.Spec.InitContainers {
		if container.Name == initContainer.Name {
			p.cpusToReuse[string(pod.UID)] = p.cpusToReuse[string(pod.UID)].Union(cset)
			return
		}
	}
	// Otherwise it is an app container.
	// Remove its cpuset from the cpuset of reusable CPUs for any new allocations.
	p.cpusToReuse[string(pod.UID)] = p.cpusToReuse[string(pod.UID)].Difference(cset)
}
func NewStaticPolicy(
	topology *topology.CPUTopology,
	numReservedCPUs int,
	reservedCPUs cpuset.CPUSet,
	affinity topologymanager.Store,
	cpuPolicyOptions map[string]string,
) (Policy, error) {
	opts, err := NewStaticPolicyOptions(cpuPolicyOptions) // align-by-socket=true
	if err != nil {
		return nil, err
	}
	err = ValidateStaticPolicyOptions(opts, topology, affinity)
	if err != nil {
		return nil, err
	}

	klog.InfoS("使用配置创建静态策略", "options", opts)

	policy := &StaticPolicy{
		topology:    topology,
		affinity:    affinity,
		cpusToReuse: make(map[string]cpuset.CPUSet),
		options:     opts,
	}

	allCPUs := topology.CPUDetails.CPUs()
	var reserved cpuset.CPUSet
	if reservedCPUs.Size() > 0 {
		reserved = reservedCPUs
	} else {
		// takeByTopology allocates CPUs associated with low-numbered cores from
		// allCPUs.
		//
		// For example: Given a system with 8 CPUs available and HT enabled,
		// if numReservedCPUs=2, then reserved={0,4}
		// 从最低序号的物理核开始 分配 预留使用的逻辑核心
		reserved, _ = policy.takeByTopology(allCPUs, numReservedCPUs)
	}

	if reserved.Size() != numReservedCPUs {
		err := fmt.Errorf("[cpumanager] 无法预留所需数量的cpu (size of %s did not equal %d)", reserved, numReservedCPUs)
		return nil, err
	}

	klog.InfoS("预留的cpu不可用于独占分配", "reservedSize", reserved.Size(), "reserved", reserved)
	policy.reserved = reserved

	return policy, nil
}

func (p *StaticPolicy) takeByTopology(availableCPUs cpuset.CPUSet, numCPUs int) (cpuset.CPUSet, error) {
	if p.options.DistributeCPUsAcrossNUMA {
		cpuGroupSize := 1
		if p.options.FullPhysicalCPUsOnly {
			cpuGroupSize = p.topology.CPUsPerCore()
		}
		return takeByTopologyNUMADistributed(p.topology, availableCPUs, numCPUs, cpuGroupSize)
	}
	return takeByTopologyNUMAPacked(p.topology, availableCPUs, numCPUs)
}

func (p *StaticPolicy) Start(s state.State) error {
	if err := p.validateState(s); err != nil {
		klog.ErrorS(err, "静态策略无效状态，请删除节点并删除策略状态文件")
		return err
	}
	return nil
}

// GetAllocatableCPUs 返回可供分配的cpu总数。
func (p *StaticPolicy) GetAllocatableCPUs(s state.State) cpuset.CPUSet {
	return p.topology.CPUDetails.CPUs().Difference(p.reserved)
}

// GetAvailableCPUs 返回未分配的cpu集减去保留的cpu集。
func (p *StaticPolicy) GetAvailableCPUs(s state.State) cpuset.CPUSet {
	return s.GetDefaultCPUSet().Difference(p.reserved)
}

// isHintSocketAligned 如果提示中的numa节点与套接字对齐，则返回true。
func (p *StaticPolicy) isHintSocketAligned(hint topologymanager.TopologyHint, minAffinitySize int) bool {
	numaNodesBitMask := hint.NUMANodeAffinity.GetBits()
	numaNodesPerSocket := p.topology.NumNUMANodes / p.topology.NumSockets
	if numaNodesPerSocket == 0 {
		return false
	}
	// minSockets refers to minimum number of socket required to satify allocation.
	// A hint is considered socket aligned if sockets across which numa nodes span is equal to minSockets
	minSockets := (minAffinitySize + numaNodesPerSocket - 1) / numaNodesPerSocket
	return p.topology.CPUDetails.SocketsInNUMANodes(numaNodesBitMask...).Size() == minSockets
}
func (p *StaticPolicy) guaranteedCPUs(pod *v1.Pod, container *v1.Container) int {
	if v1qos.GetPodQOS(pod) != v1.PodQOSGuaranteed {
		return 0
	}
	cpuQuantity := container.Resources.Requests[v1.ResourceCPU]
	if cpuQuantity.Value()*1000 != cpuQuantity.MilliValue() {
		return 0
	}
	// Safe downcast to do for all systems with < 2.1 billion CPUs.
	// Per the language spec, `int` is guaranteed to be at least 32 bits wide.
	// https://golang.org/ref/spec#Numeric_types
	return int(cpuQuantity.Value())
}

// 获取整个pod 中一共要使用到的最大cpu
func (p *StaticPolicy) podGuaranteedCPUs(pod *v1.Pod) int { // 保证
	// The maximum of requested CPUs by init containers.
	requestedByInitContainers := 0
	for _, container := range pod.Spec.InitContainers {
		if _, ok := container.Resources.Requests[v1.ResourceCPU]; !ok {
			continue
		}
		requestedCPU := p.guaranteedCPUs(pod, &container)
		if requestedCPU > requestedByInitContainers {
			requestedByInitContainers = requestedCPU
		}
	}
	// The sum of requested CPUs by app containers.
	requestedByAppContainers := 0
	for _, container := range pod.Spec.Containers {
		if _, ok := container.Resources.Requests[v1.ResourceCPU]; !ok {
			continue
		}
		requestedByAppContainers += p.guaranteedCPUs(pod, &container)
	}

	if requestedByInitContainers > requestedByAppContainers {
		return requestedByInitContainers
	}
	return requestedByAppContainers
}

// getAssignedCPUsOfSiblings 返回在给定的podUID中，除了给定的container之外的所有container的分配的CPU。
func getAssignedCPUsOfSiblings(s state.State, podUID string, containerName string) cpuset.CPUSet {
	assignments := s.GetCPUAssignments()
	cset := cpuset.NewCPUSet()
	for name, cpus := range assignments[podUID] {
		if containerName == name {
			continue
		}
		cset = cset.Union(cpus)
	}
	return cset
}

func (p *StaticPolicy) RemoveContainer(s state.State, podUID string, containerName string) error {
	klog.InfoS("Static policy: RemoveContainer", "podUID", podUID, "containerName", containerName)
	cpusInUse := getAssignedCPUsOfSiblings(s, podUID, containerName)
	if toRelease, ok := s.GetCPUSet(podUID, containerName); ok {
		s.Delete(podUID, containerName)
		// 修改共享池，将释放的CPU添加进去。
		toRelease = toRelease.Difference(cpusInUse)
		s.SetDefaultCPUSet(s.GetDefaultCPUSet().Union(toRelease))
	}
	return nil
}

func (p *StaticPolicy) allocateCPUs(s state.State, numCPUs int, numaAffinity bitmask.BitMask, reusableCPUs cpuset.CPUSet) (cpuset.CPUSet, error) {
	klog.InfoS("AllocateCPUs", "numCPUs", numCPUs, "socket", numaAffinity)

	allocatableCPUs := p.GetAvailableCPUs(s).Union(reusableCPUs)

	// 如果numaAffinity中存在对齐的CPU，首先尝试获取这些CPU。
	result := cpuset.NewCPUSet()
	if numaAffinity != nil {
		alignedCPUs := p.getAlignedCPUs(numaAffinity, allocatableCPUs)

		numAlignedToAlloc := alignedCPUs.Size()
		if numCPUs < numAlignedToAlloc {
			numAlignedToAlloc = numCPUs
		}

		alignedCPUs, err := p.takeByTopology(alignedCPUs, numAlignedToAlloc)
		if err != nil {
			return cpuset.NewCPUSet(), err
		}

		result = result.Union(alignedCPUs) // 先分配的
	}

	// 在尝试获取对齐的CPU后，从剩余的可用CPU中获取任何剩余的CPU。
	remainingCPUs, err := p.takeByTopology(allocatableCPUs.Difference(result), numCPUs-result.Size())
	if err != nil {
		return cpuset.NewCPUSet(), err
	}
	result = result.Union(remainingCPUs) // 分配的

	// 从缓存池里移除已经分配的
	s.SetDefaultCPUSet(s.GetDefaultCPUSet().Difference(result))

	klog.InfoS("AllocateCPUs", "result", result)
	return result, nil
}
