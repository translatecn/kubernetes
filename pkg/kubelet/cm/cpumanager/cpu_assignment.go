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
	"math"
	"sort"

	"k8s.io/klog/v2"

	"k8s.io/kubernetes/pkg/kubelet/cm/cpumanager/topology"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpuset"
)

// LoopControl controls the behavior of the cpu accumulator loop logic
type LoopControl int

// Possible loop control outcomes
const (
	Continue LoopControl = iota
	Break
)

type mapIntInt map[int]int

func (m mapIntInt) Clone() mapIntInt {
	cp := make(mapIntInt, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

func (m mapIntInt) Keys() []int {
	var keys []int
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func (m mapIntInt) Values(keys ...int) []int {
	if keys == nil {
		keys = m.Keys()
	}
	var values []int
	for _, k := range keys {
		values = append(values, m[k])
	}
	return values
}

func sum(xs []int) int {
	var s int
	for _, x := range xs {
		s += x
	}
	return s
}

func mean(xs []int) float64 {
	var sum float64
	for _, x := range xs {
		sum += float64(x)
	}
	m := sum / float64(len(xs))
	return math.Round(m*1000) / 1000
}

func standardDeviation(xs []int) float64 {
	m := mean(xs)
	var sum float64
	for _, x := range xs {
		sum += (float64(x) - m) * (float64(x) - m)
	}
	s := math.Sqrt(sum / float64(len(xs)))
	return math.Round(s*1000) / 1000
}

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

type numaOrSocketsFirstFuncs interface {
	takeFullFirstLevel()           // 从第一级（NUMA节点或插槽）中获取所有可用的资源。
	takeFullSecondLevel()          // 从第二级（NUMA节点或插槽）中获取所有可用的资源。
	sortAvailableNUMANodes() []int // 对可用的NUMA节点进行排序，并返回排序后的NUMA节点列表。
	sortAvailableSockets() []int   // 对可用的插槽进行排序，并返回排序后的插槽列表。
	sortAvailableCores() []int     // 对可用的核心进行排序，并返回排序后的核心列表。
}

type numaFirst struct{ acc *cpuAccumulator }
type socketsFirst struct{ acc *cpuAccumulator }

var _ numaOrSocketsFirstFuncs = (*numaFirst)(nil)
var _ numaOrSocketsFirstFuncs = (*socketsFirst)(nil)

// 如果NUMA节点在内存层次结构中高于插槽，则我们首先从NUMA节点集合中获取。
func (n *numaFirst) takeFullFirstLevel() {
	n.acc.takeFullNUMANodes()
}

// If NUMA nodes are higher in the memory hierarchy than sockets, then we take
// from the set of sockets as the second level.
func (n *numaFirst) takeFullSecondLevel() {
	n.acc.takeFullSockets()
}

// If NUMA nodes are higher in the memory hierarchy than sockets, then just
// sort the NUMA nodes directly, and return them.

// If NUMA nodes are higher in the memory hierarchy than sockets, then we need
// to pull the set of sockets out of each sorted NUMA node, and accumulate the
// partial order across them.
func (n *numaFirst) sortAvailableSockets() []int {
	var result []int
	for _, numa := range n.sortAvailableNUMANodes() {
		sockets := n.acc.details.SocketsInNUMANodes(numa).ToSliceNoSort()
		n.acc.sort(sockets, n.acc.details.CPUsInSockets)
		result = append(result, sockets...)
	}
	return result
}

// If NUMA nodes are higher in the memory hierarchy than sockets, then
// cores sit directly below sockets in the memory hierarchy.
func (n *numaFirst) sortAvailableCores() []int {
	var result []int
	for _, socket := range n.acc.sortAvailableSockets() {
		cores := n.acc.details.CoresInSockets(socket).ToSliceNoSort()
		n.acc.sort(cores, n.acc.details.CPUsInCores)
		result = append(result, cores...)
	}
	return result
}

// If sockets are higher in the memory hierarchy than NUMA nodes, then we take
// from the set of sockets as the first level.
func (s *socketsFirst) takeFullFirstLevel() {
	s.acc.takeFullSockets()
}

// If sockets are higher in the memory hierarchy than NUMA nodes, then we take
// from the set of NUMA Nodes as the second level.
func (s *socketsFirst) takeFullSecondLevel() {
	s.acc.takeFullNUMANodes()
}

// If sockets are higher in the memory hierarchy than NUMA nodes, then we need
// to pull the set of NUMA nodes out of each sorted Socket, and accumulate the
// partial order across them.
func (s *socketsFirst) sortAvailableNUMANodes() []int {
	var result []int
	for _, socket := range s.sortAvailableSockets() {
		numas := s.acc.details.NUMANodesInSockets(socket).ToSliceNoSort()
		s.acc.sort(numas, s.acc.details.CPUsInNUMANodes)
		result = append(result, numas...)
	}
	return result
}

// If sockets are higher in the memory hierarchy than NUMA nodes, then just
// sort the sockets directly, and return them.
func (s *socketsFirst) sortAvailableSockets() []int {
	sockets := s.acc.details.Sockets().ToSliceNoSort()
	s.acc.sort(sockets, s.acc.details.CPUsInSockets)
	return sockets
}

// If sockets are higher in the memory hierarchy than NUMA nodes, then cores
// sit directly below NUMA Nodes in the memory hierarchy.
func (s *socketsFirst) sortAvailableCores() []int {
	var result []int
	for _, numa := range s.acc.sortAvailableNUMANodes() {
		cores := s.acc.details.CoresInNUMANodes(numa).ToSliceNoSort()
		s.acc.sort(cores, s.acc.details.CPUsInCores)
		result = append(result, cores...)
	}
	return result
}

type cpuAccumulator struct {
	topo               *topology.CPUTopology   // CPU的拓扑结构
	details            topology.CPUDetails     // 计算后的 CPU的详细信息
	numCPUsNeeded      int                     // 所需的CPU数量
	result             cpuset.CPUSet           // 已经分配的CPU集合
	numaOrSocketsFirst numaOrSocketsFirstFuncs // 用于确定从NUMA节点还是插槽中获取CPU
}

// Returns true if the supplied socket is fully available in `topoDetails`.
func (a *cpuAccumulator) isSocketFree(socketID int) bool {
	return a.details.CPUsInSockets(socketID).Size() == a.topo.CPUsPerSocket()
}

// Returns true if the supplied core is fully available in `topoDetails`.
func (a *cpuAccumulator) isCoreFree(coreID int) bool {
	return a.details.CPUsInCores(coreID).Size() == a.topo.CPUsPerCore()
}

// Returns free socket IDs as a slice sorted by sortAvailableSockets().
func (a *cpuAccumulator) freeSockets() []int {
	free := []int{}
	for _, socket := range a.sortAvailableSockets() {
		if a.isSocketFree(socket) {
			free = append(free, socket)
		}
	}
	return free
}

// Returns free core IDs as a slice sorted by sortAvailableCores().
func (a *cpuAccumulator) freeCores() []int {
	free := []int{}
	for _, core := range a.sortAvailableCores() {
		if a.isCoreFree(core) {
			free = append(free, core)
		}
	}
	return free
}

// Returns free CPU IDs as a slice sorted by sortAvailableCPUs().
func (a *cpuAccumulator) freeCPUs() []int {
	return a.sortAvailableCPUs()
}

// Sorts the provided list of NUMA nodes/sockets/cores/cpus referenced in 'ids'
// by the number of available CPUs contained within them (smallest to largest).
// The 'getCPU()' paramater defines the function that should be called to
// retrieve the list of available CPUs for the type being referenced. If two
// NUMA nodes/sockets/cores/cpus have the same number of available CPUs, they
// are sorted in ascending order by their id.
func (a *cpuAccumulator) sort(ids []int, getCPUs func(ids ...int) cpuset.CPUSet) {
	sort.Slice(ids,
		func(i, j int) bool {
			iCPUs := getCPUs(ids[i])
			jCPUs := getCPUs(ids[j])
			if iCPUs.Size() < jCPUs.Size() {
				return true
			}
			if iCPUs.Size() > jCPUs.Size() {
				return false
			}
			return ids[i] < ids[j]
		})
}

// Sort all sockets with free CPUs.
func (a *cpuAccumulator) sortAvailableSockets() []int {
	return a.numaOrSocketsFirst.sortAvailableSockets()
}

// Sort all cores with free CPUs:
func (a *cpuAccumulator) sortAvailableCores() []int {
	return a.numaOrSocketsFirst.sortAvailableCores()
}

func (a *cpuAccumulator) takeFullNUMANodes() {
	for _, numa := range a.freeNUMANodes() {
		cpusInNUMANode := a.topo.CPUDetails.CPUsInNUMANodes(numa)
		if !a.needs(cpusInNUMANode.Size()) {
			continue
		}
		klog.V(4).InfoS("takeFullNUMANodes: claiming NUMA node", "numa", numa)
		a.take(cpusInNUMANode)
	}
}

func (a *cpuAccumulator) takeFullSockets() {
	for _, socket := range a.freeSockets() {
		cpusInSocket := a.topo.CPUDetails.CPUsInSockets(socket)
		if !a.needs(cpusInSocket.Size()) { //
			continue
		}
		klog.V(4).InfoS("takeFullSockets: claiming socket", "socket", socket)
		a.take(cpusInSocket)
	}
}

func (a *cpuAccumulator) needs(n int) bool {
	return a.numCPUsNeeded >= n
}

func (a *cpuAccumulator) isSatisfied() bool {
	return a.numCPUsNeeded < 1
}

func (a *cpuAccumulator) isFailed() bool {
	return a.numCPUsNeeded > a.details.CPUs().Size()
}

// ------------------------------------------------------------------------------------------------------------

func newCPUAccumulator(topo *topology.CPUTopology, availableCPUs cpuset.CPUSet, numCPUs int) *cpuAccumulator {
	acc := &cpuAccumulator{
		topo:          topo,
		details:       topo.CPUDetails.KeepOnly(availableCPUs),
		numCPUsNeeded: numCPUs,
		result:        cpuset.NewCPUSet(),
	}

	if topo.NumSockets >= topo.NumNUMANodes {
		acc.numaOrSocketsFirst = &numaFirst{acc}
	} else {
		acc.numaOrSocketsFirst = &socketsFirst{acc}
	}

	return acc
}

func (a *cpuAccumulator) sortAvailableNUMANodes() []int {
	return a.numaOrSocketsFirst.sortAvailableNUMANodes()
}
func (n *numaFirst) sortAvailableNUMANodes() []int {
	numas := n.acc.details.NUMANodes().ToSliceNoSort()
	n.acc.sort(numas, n.acc.details.CPUsInNUMANodes)
	return numas
}

// Returns true if the supplied NUMANode is fully available in `topoDetails`.
func (a *cpuAccumulator) isNUMANodeFree(numaID int) bool {
	return a.details.CPUsInNUMANodes(numaID).Size() == a.topo.CPUDetails.CPUsInNUMANodes(numaID).Size()
}

func (a *cpuAccumulator) freeNUMANodes() []int {
	free := []int{}
	for _, numa := range a.sortAvailableNUMANodes() {
		if a.isNUMANodeFree(numa) {
			free = append(free, numa)
		}
	}
	return free
}

// 占用一个物理核
func (a *cpuAccumulator) takeFullCores() {
	for _, core := range a.freeCores() {
		cpusInCore := a.topo.CPUDetails.CPUsInCores(core)
		if !a.needs(cpusInCore.Size()) {
			continue // need < cpusInCore
		}
		klog.V(4).InfoS("takeFullCores: claiming core", "core", core)
		a.take(cpusInCore)
	}
}

func (a *cpuAccumulator) take(cpus cpuset.CPUSet) {
	a.result = a.result.Union(cpus) // 已经分配的CPU集合
	a.details = a.details.KeepOnly(a.details.CPUs().Difference(a.result))
	a.numCPUsNeeded -= cpus.Size()
}

func (a *cpuAccumulator) takeRemainingCPUs() {
	for _, cpu := range a.sortAvailableCPUs() {
		klog.V(4).InfoS("takeRemainingCPUs: claiming CPU", "cpu", cpu)
		a.take(cpuset.NewCPUSet(cpu))
		if a.isSatisfied() {
			return
		}
	}
}

// Sort all available CPUs:
// - First by core using sortAvailableCores().
// - Then within each core, using the sort() algorithm defined above.
func (a *cpuAccumulator) sortAvailableCPUs() []int {
	var result []int
	for _, core := range a.sortAvailableCores() {
		cpus := a.details.CPUsInCores(core).ToSliceNoSort()
		sort.Ints(cpus)
		result = append(result, cpus...)
	}
	return result
}

// 打包分配
func takeByTopologyNUMAPacked(topo *topology.CPUTopology, availableCPUs cpuset.CPUSet, numCPUs int) (cpuset.CPUSet, error) {
	acc := newCPUAccumulator(topo, availableCPUs, numCPUs)
	if acc.isSatisfied() {
		return acc.result, nil
	}
	if acc.isFailed() {
		return cpuset.NewCPUSet(), fmt.Errorf("没有足够的cpu来满足请求")
	}

	// 基于拓扑的最佳适配
	// 1. 如果可用并且容器需要至少一个NUMA节点或一个插槽的CPU，则获取整个NUMA节点和插槽。如果NUMA节点映射到一个或多个插槽，则首先从NUMA节点中获取。否则，首先从插槽中获取。
	acc.numaOrSocketsFirst.takeFullFirstLevel()
	var _ = new(numaFirst).takeFullFirstLevel
	if acc.isSatisfied() {
		return acc.result, nil
	}
	acc.numaOrSocketsFirst.takeFullSecondLevel()
	if acc.isSatisfied() {
		return acc.result, nil
	}
	// 2. 如果可用并且容器需要至少一个核心的CPU，则获取整个核心。
	acc.takeFullCores() // need < cpusInCore
	if acc.isSatisfied() {
		return acc.result, nil
	}
	// 3. 获取单个线程，优先填充与已经在此分配中获取的整个核心位于同一插槽上的部分分配核心。
	acc.takeRemainingCPUs()
	if acc.isSatisfied() {
		return acc.result, nil
	}

	return cpuset.NewCPUSet(), fmt.Errorf("failed to allocate cpus")
}

func (a *cpuAccumulator) rangeNUMANodesNeededToSatisfy(cpuGroupSize int) (int, int) {
	// 获取系统中的NUMA节点总数。
	numNUMANodes := a.topo.CPUDetails.NUMANodes().Size()

	// 获取具有可用CPU的NUMA节点的总数。
	numNUMANodesAvailable := a.details.NUMANodes().Size()

	// 获取系统中的CPU总数。
	numCPUs := a.topo.CPUDetails.CPUs().Size()

	// 获取系统中的'cpuGroups'总数。 物理核
	numCPUGroups := (numCPUs-1)/cpuGroupSize + 1

	// 计算系统中每个NUMA节点的'cpuGroups'数量（向上取整）。
	numCPUGroupsPerNUMANode := (numCPUGroups-1)/numNUMANodes + 1

	// 计算所有NUMA节点上可用的'cpuGroups'数量以及需要分配的'cpuGroups'数量（向上取整）。
	numCPUGroupsNeeded := (a.numCPUsNeeded-1)/cpuGroupSize + 1

	// 计算满足分配所需的最小NUMA节点数量（向上取整）。
	minNUMAs := (numCPUGroupsNeeded-1)/numCPUGroupsPerNUMANode + 1

	// 计算满足分配所需的最大NUMA节点数量。
	maxNUMAs := min(numCPUGroupsNeeded, numNUMANodesAvailable)

	return minNUMAs, maxNUMAs
}

// iterateCombinations walks through all n-choose-k subsets of size k in n and
// calls function 'f()' on each subset. For example, if n={0,1,2}, and k=2,
// then f() will be called on the subsets {0,1}, {0,2}. and {1,2}. If f() ever
// returns 'Break', we break early and exit the loop.
func (a *cpuAccumulator) iterateCombinations(n []int, k int, f func([]int) LoopControl) {
	if k < 1 {
		return
	}

	var helper func(n []int, k int, start int, accum []int, f func([]int) LoopControl) LoopControl
	helper = func(n []int, k int, start int, accum []int, f func([]int) LoopControl) LoopControl {
		if k == 0 {
			return f(accum)
		}
		for i := start; i <= len(n)-k; i++ {
			control := helper(n, k-1, i+1, append(accum, n[i]), f)
			if control == Break {
				return Break
			}
		}
		return Continue
	}

	helper(n, k, 0, []int{}, f)
}

// returns a CPUSet of size 'numCPUs'.
//
// It generates this CPUset by allocating CPUs from 'availableCPUs' according
// to the algorithm outlined in KEP-2902:
//
// https://github.com/kubernetes/enhancements/tree/e7f51ffbe2ee398ffd1fba4a6d854f276bfad9fb/keps/sig-node/2902-cpumanager-distribute-cpus-policy-option
//
// This algorithm evenly distribute CPUs across NUMA nodes in cases where more
// than one NUMA node is required to satisfy the allocation. This is in
// contrast to the takeByTopologyNUMAPacked algorithm, which attempts to 'pack'
// CPUs onto NUMA nodes and fill them up before moving on to the next one.
//
// At a high-level this algorithm can be summarized as:
//
// For each NUMA single node:
//   - If all requested CPUs can be allocated from this NUMA node;
//     --> Do the allocation by running takeByTopologyNUMAPacked() over the
//     available CPUs in that NUMA node and return
//
// Otherwise, for each pair of NUMA nodes:
//   - If the set of requested CPUs (modulo 2) can be evenly split across
//     the 2 NUMA nodes; AND
//   - Any remaining CPUs (after the modulo operation) can be striped across
//     some subset of the NUMA nodes;
//     --> Do the allocation by running takeByTopologyNUMAPacked() over the
//     available CPUs in both NUMA nodes and return
//
// Otherwise, for each 3-tuple of NUMA nodes:
//   - If the set of requested CPUs (modulo 3) can be evenly distributed
//     across the 3 NUMA nodes; AND
//   - Any remaining CPUs (after the modulo operation) can be striped across
//     some subset of the NUMA nodes;
//     --> Do the allocation by running takeByTopologyNUMAPacked() over the
//     available CPUs in all three NUMA nodes and return
//
// ...
//
// Otherwise, for the set of all NUMA nodes:
//   - If the set of requested CPUs (modulo NUM_NUMA_NODES) can be evenly
//     distributed across all NUMA nodes; AND
//   - Any remaining CPUs (after the modulo operation) can be striped across
//     some subset of the NUMA nodes;
//     --> Do the allocation by running takeByTopologyNUMAPacked() over the
//     available CPUs in all NUMA nodes and return
//
// If none of the above conditions can be met, then resort back to a
// best-effort fit of packing CPUs into NUMA nodes by calling
// takeByTopologyNUMAPacked() over all available CPUs.
//
// NOTE: A "balance score" will be calculated to help find the best subset of
// NUMA nodes to allocate any 'remainder' CPUs from (in cases where the total
// number of CPUs to allocate cannot be evenly distributed across the chosen
// set of NUMA nodes). This "balance score" is calculated as the standard
// deviation of how many CPUs will be available on each NUMA node after all
// evenly distributed and remainder CPUs are allocated. The subset with the
// lowest "balance score" will receive the CPUs in order to keep the overall
// allocation of CPUs as "balanced" as possible.
//
// NOTE: This algorithm has been generalized to take an additional
// 'cpuGroupSize' parameter to ensure that CPUs are always allocated in groups
// of size 'cpuGroupSize' according to the algorithm described above. This is
// important, for example, to ensure that all CPUs (i.e. all hyperthreads) from
// a single core are allocated together.
// 从给定的所有CPU中分配低编号的核心  在NUMA节点之间均匀分配CPU
func takeByTopologyNUMADistributed(topo *topology.CPUTopology, availableCPUs cpuset.CPUSet, numCPUs int, cpuGroupSize int) (cpuset.CPUSet, error) {
	// If the number of CPUs requested cannot be handed out in chunks of
	// 'cpuGroupSize', then we just call out the packing algorithm since we
	// can't distribute CPUs in this chunk size.
	if (numCPUs % cpuGroupSize) != 0 { // 使用超线程了
		return takeByTopologyNUMAPacked(topo, availableCPUs, numCPUs)
	}
	// 否则，构建一个累加器以开始分配CPU。
	acc := newCPUAccumulator(topo, availableCPUs, numCPUs)
	if acc.isSatisfied() {
		return acc.result, nil
	}
	if acc.isFailed() {
		return cpuset.NewCPUSet(), fmt.Errorf("not enough cpus available to satisfy request")
	}

	// Get the list of NUMA nodes represented by the set of CPUs in 'availableCPUs'.
	numas := acc.sortAvailableNUMANodes()
	//计算能够满足此请求的NUMA节点的最小和最大可能数量。这用于优化下面循环中需要进行的迭代次数。
	minNUMAs, maxNUMAs := acc.rangeNUMANodesNeededToSatisfy(cpuGroupSize)

	//尝试使用1、2、3... NUMA节点的组合，直到找到一个可以均匀分配CPU的组合。为了优化计算，我们不总是从1开始，结束于len(numas)。
	//相反，我们使用上面计算得到的'minNUMAs'和'maxNUMAs'的值。
	for k := minNUMAs; k <= maxNUMAs; k++ {
		// 通过迭代不同的n-choose-k（从n个元素中选择k个元素）的NUMA节点组合，寻找最佳的NUMA节点组合，以便在它们之间均匀分配CPU。
		var bestBalance float64 = math.MaxFloat64
		var bestRemainder []int = nil
		var bestCombo []int = nil
		acc.iterateCombinations(numas, k, func(combo []int) LoopControl {

			if bestBalance == 0 {
				return Break
			}

			// Check that this combination of NUMA nodes has enough CPUs to
			// satisfy the allocation overall.
			cpus := acc.details.CPUsInNUMANodes(combo...)
			if cpus.Size() < numCPUs {
				return Continue
			}

			// Check that CPUs can be handed out in groups of size
			// 'cpuGroupSize' across the NUMA nodes in this combo.
			numCPUGroups := 0
			for _, numa := range combo {
				numCPUGroups += (acc.details.CPUsInNUMANodes(numa).Size() / cpuGroupSize)
			}
			if (numCPUGroups * cpuGroupSize) < numCPUs {
				return Continue
			}

			// Check that each NUMA node in this combination can allocate an
			// even distribution of CPUs in groups of size 'cpuGroupSize',
			// modulo some remainder.
			distribution := (numCPUs / len(combo) / cpuGroupSize) * cpuGroupSize
			for _, numa := range combo {
				cpus := acc.details.CPUsInNUMANodes(numa)
				if cpus.Size() < distribution {
					return Continue
				}
			}

			// Calculate how many CPUs will be available on each NUMA node in
			// the system after allocating an even distribution of CPU groups
			// of size 'cpuGroupSize' from each NUMA node in 'combo'. This will
			// be used in the "balance score" calculation to help decide if
			// this combo should ultimately be chosen.
			availableAfterAllocation := make(mapIntInt, len(numas))
			for _, numa := range numas {
				availableAfterAllocation[numa] = acc.details.CPUsInNUMANodes(numa).Size()
			}
			for _, numa := range combo {
				availableAfterAllocation[numa] -= distribution
			}

			// Check if there are any remaining CPUs to distribute across the
			// NUMA nodes once CPUs have been evenly distributed in groups of
			// size 'cpuGroupSize'.
			remainder := numCPUs - (distribution * len(combo))

			// Get a list of NUMA nodes to consider pulling the remainder CPUs
			// from. This list excludes NUMA nodes that don't have at least
			// 'cpuGroupSize' CPUs available after being allocated
			// 'distribution' number of CPUs.
			var remainderCombo []int
			for _, numa := range combo {
				if availableAfterAllocation[numa] >= cpuGroupSize {
					remainderCombo = append(remainderCombo, numa)
				}
			}

			// Declare a set of local variables to help track the "balance
			// scores" calculated when using different subsets of
			// 'remainderCombo' to allocate remainder CPUs from.
			var bestLocalBalance float64 = math.MaxFloat64
			var bestLocalRemainder []int = nil

			// If there aren't any remainder CPUs to allocate, then calculate
			// the "balance score" of this combo as the standard deviation of
			// the values contained in 'availableAfterAllocation'.
			if remainder == 0 {
				bestLocalBalance = standardDeviation(availableAfterAllocation.Values())
				bestLocalRemainder = nil
			}

			// Otherwise, find the best "balance score" when allocating the
			// remainder CPUs across different subsets of NUMA nodes in 'remainderCombo'.
			// These remainder CPUs are handed out in groups of size 'cpuGroupSize'.
			// We start from k=len(remainderCombo) and walk down to k=1 so that
			// we continue to distribute CPUs as much as possible across
			// multiple NUMA nodes.
			for k := len(remainderCombo); remainder > 0 && k >= 1; k-- {
				acc.iterateCombinations(remainderCombo, k, func(subset []int) LoopControl {
					// Make a local copy of 'remainder'.
					remainder := remainder

					// Make a local copy of 'availableAfterAllocation'.
					availableAfterAllocation := availableAfterAllocation.Clone()

					// If this subset is not capable of allocating all
					// remainder CPUs, continue to the next one.
					if sum(availableAfterAllocation.Values(subset...)) < remainder {
						return Continue
					}

					// For all NUMA nodes in 'subset', walk through them,
					// removing 'cpuGroupSize' number of CPUs from each
					// until all remainder CPUs have been accounted for.
					for remainder > 0 {
						for _, numa := range subset {
							if remainder == 0 {
								break
							}
							if availableAfterAllocation[numa] < cpuGroupSize {
								continue
							}
							availableAfterAllocation[numa] -= cpuGroupSize
							remainder -= cpuGroupSize
						}
					}

					// Calculate the "balance score" as the standard deviation
					// of the number of CPUs available on all NUMA nodes in the
					// system after the remainder CPUs have been allocated
					// across 'subset' in groups of size 'cpuGroupSize'.
					balance := standardDeviation(availableAfterAllocation.Values())
					if balance < bestLocalBalance {
						bestLocalBalance = balance
						bestLocalRemainder = subset
					}

					return Continue
				})
			}

			// If the best "balance score" for this combo is less than the
			// lowest "balance score" of all previous combos, then update this
			// combo (and remainder set) to be the best one found so far.
			if bestLocalBalance < bestBalance {
				bestBalance = bestLocalBalance
				bestRemainder = bestLocalRemainder
				bestCombo = combo
			}

			return Continue
		})

		// If we made it through all of the iterations above without finding a
		// combination of NUMA nodes that can properly balance CPU allocations,
		// then move on to the next larger set of NUMA node combinations.
		if bestCombo == nil {
			continue
		}

		// Otherwise, start allocating CPUs from the NUMA node combination
		// chosen. First allocate an even distribution of CPUs in groups of
		// size 'cpuGroupSize' from 'bestCombo'.
		distribution := (numCPUs / len(bestCombo) / cpuGroupSize) * cpuGroupSize
		for _, numa := range bestCombo {
			cpus, _ := takeByTopologyNUMAPacked(acc.topo, acc.details.CPUsInNUMANodes(numa), distribution)
			acc.take(cpus)
		}

		// Then allocate any remaining CPUs in groups of size 'cpuGroupSize'
		// from each NUMA node in the remainder set.
		remainder := numCPUs - (distribution * len(bestCombo))
		for remainder > 0 {
			for _, numa := range bestRemainder {
				if remainder == 0 {
					break
				}
				if acc.details.CPUsInNUMANodes(numa).Size() < cpuGroupSize {
					continue
				}
				cpus, _ := takeByTopologyNUMAPacked(acc.topo, acc.details.CPUsInNUMANodes(numa), cpuGroupSize)
				acc.take(cpus)
				remainder -= cpuGroupSize
			}
		}

		// If we haven't allocated all of our CPUs at this point, then something
		// went wrong in our accounting and we should error out.
		if acc.numCPUsNeeded > 0 {
			return cpuset.NewCPUSet(), fmt.Errorf("accounting error, not enough CPUs allocated, remaining: %v", acc.numCPUsNeeded)
		}

		// Likewise, if we have allocated too many CPUs at this point, then something
		// went wrong in our accounting and we should error out.
		if acc.numCPUsNeeded < 0 {
			return cpuset.NewCPUSet(), fmt.Errorf("accounting error, too many CPUs allocated, remaining: %v", acc.numCPUsNeeded)
		}

		// Otherwise, return the result
		return acc.result, nil
	}

	// If we never found a combination of NUMA nodes that we could properly
	// distribute CPUs across, fall back to the packing algorithm.
	return takeByTopologyNUMAPacked(topo, availableCPUs, numCPUs)
}
