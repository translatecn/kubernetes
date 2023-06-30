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
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/kubelet/cm/topologymanager/bitmask"
)

// Policy interface for Topology Manager Pod Admit Result
type Policy interface {
	Name() string                                                          // 拓扑策略
	Merge(providersHints []map[string][]TopologyHint) (TopologyHint, bool) // 根据来自不同提示提供者的拓扑提示信息,合并生成一个最终的拓扑提示,并返回一个布尔值,表示是否应该接受该拓扑提示.
}

type HintMerger struct {
	NUMAInfo                      *NUMAInfo                                                                 //
	Hints                         [][]TopologyHint                                                          // 不同资源,符合资源需求（numa 数量）的 numa 组合
	BestNonPreferredAffinityCount int                                                                       // 计算给定提示提供者的最小亲和计数中的最大值.
	CompareNUMAAffinityMasks      func(candidate *TopologyHint, current *TopologyHint) (best *TopologyHint) //
}

func (m HintMerger) compare(current *TopologyHint, candidate *TopologyHint) *TopologyHint {
	// Only consider candidates that result in a NUMANodeAffinity > 0 to
	// replace the current bestHint.
	if candidate.NUMANodeAffinity.Count() == 0 {
		return current
	}

	// If no current bestHint is set, return the candidate as the bestHint.
	if current == nil {
		return candidate
	}

	// If the current bestHint is non-preferred and the candidate hint is
	// preferred, always choose the preferred hint over the non-preferred one.
	if !current.Preferred && candidate.Preferred {
		return candidate
	}

	// If the current bestHint is preferred and the candidate hint is
	// non-preferred, never update the bestHint, regardless of how
	// the candidate hint's affinity mask compares to the current
	// hint's affinity mask.
	if current.Preferred && !candidate.Preferred {
		return current
	}

	// If the current bestHint and the candidate hint are both preferred,
	// then only consider fitter NUMANodeAffinity
	if current.Preferred && candidate.Preferred {
		return m.CompareNUMAAffinityMasks(current, candidate) // 尽可能使用numa 更低的,   numa 节点之间平均距离更低的
	}

	// The only case left is if the current best bestHint and the candidate
	// hint are both non-preferred. In this case, try and find a hint whose
	// affinity count is as close to (but not higher than) the
	// bestNonPreferredAffinityCount as possible. To do this we need to
	// consider the following cases and react accordingly:
	//
	//   1. current.NUMANodeAffinity.Count() >  bestNonPreferredAffinityCount
	//   2. current.NUMANodeAffinity.Count() == bestNonPreferredAffinityCount
	//   3. current.NUMANodeAffinity.Count() <  bestNonPreferredAffinityCount
	//
	// For case (1), the current bestHint is larger than the
	// bestNonPreferredAffinityCount, so updating to fitter mergeHint
	// is preferred over staying where we are.
	//
	// For case (2), the current bestHint is equal to the
	// bestNonPreferredAffinityCount, so we would like to stick with what
	// we have *unless* the candidate hint is also equal to
	// bestNonPreferredAffinityCount and it is fitter.
	//
	// For case (3), the current bestHint is less than
	// bestNonPreferredAffinityCount, so we would like to creep back up to
	// bestNonPreferredAffinityCount as close as we can. There are three
	// cases to consider here:
	//
	//   3a. candidate.NUMANodeAffinity.Count() >  bestNonPreferredAffinityCount
	//   3b. candidate.NUMANodeAffinity.Count() == bestNonPreferredAffinityCount
	//   3c. candidate.NUMANodeAffinity.Count() <  bestNonPreferredAffinityCount
	//
	// For case (3a), we just want to stick with the current bestHint
	// because choosing a new hint that is greater than
	// bestNonPreferredAffinityCount would be counter-productive.
	//
	// For case (3b), we want to immediately update bestHint to the
	// candidate hint, making it now equal to bestNonPreferredAffinityCount.
	//
	// For case (3c), we know that *both* the current bestHint and the
	// candidate hint are less than bestNonPreferredAffinityCount, so we
	// want to choose one that brings us back up as close to
	// bestNonPreferredAffinityCount as possible. There are three cases to
	// consider here:
	//
	//   3ca. candidate.NUMANodeAffinity.Count() >  current.NUMANodeAffinity.Count()
	//   3cb. candidate.NUMANodeAffinity.Count() <  current.NUMANodeAffinity.Count()
	//   3cc. candidate.NUMANodeAffinity.Count() == current.NUMANodeAffinity.Count()
	//
	// For case (3ca), we want to immediately update bestHint to the
	// candidate hint because that will bring us closer to the (higher)
	// value of bestNonPreferredAffinityCount.
	//
	// For case (3cb), we want to stick with the current bestHint because
	// choosing the candidate hint would strictly move us further away from
	// the bestNonPreferredAffinityCount.
	//
	// Finally, for case (3cc), we know that the current bestHint and the
	// candidate hint are equal, so we simply choose the fitter of the 2.

	// Case 1
	if current.NUMANodeAffinity.Count() > m.BestNonPreferredAffinityCount {
		return m.CompareNUMAAffinityMasks(current, candidate)
	}
	// Case 2
	if current.NUMANodeAffinity.Count() == m.BestNonPreferredAffinityCount {
		if candidate.NUMANodeAffinity.Count() != m.BestNonPreferredAffinityCount {
			return current
		}
		return m.CompareNUMAAffinityMasks(current, candidate)
	}
	// Case 3a
	if candidate.NUMANodeAffinity.Count() > m.BestNonPreferredAffinityCount {
		return current
	}
	// Case 3b
	if candidate.NUMANodeAffinity.Count() == m.BestNonPreferredAffinityCount {
		return candidate
	}

	// Case 3ca
	if candidate.NUMANodeAffinity.Count() > current.NUMANodeAffinity.Count() {
		return candidate
	}
	// Case 3cb
	if candidate.NUMANodeAffinity.Count() < current.NUMANodeAffinity.Count() {
		return current
	}

	// Case 3cc
	return m.CompareNUMAAffinityMasks(current, candidate)

}

// Iterate over all permutations of hints in 'allProviderHints [][]TopologyHint'.
//
// This procedure is implemented as a recursive function over the set of hints
// in 'allproviderHints[i]'. It applies the function 'callback' to each
// permutation as it is found. It is the equivalent of:
//
// for i := 0; i < len(providerHints[0]); i++
//
//	for j := 0; j < len(providerHints[1]); j++
//	    for k := 0; k < len(providerHints[2]); k++
//	        ...
//	        for z := 0; z < len(providerHints[-1]); z++
//	            permutation := []TopologyHint{
//	                providerHints[0][i],
//	                providerHints[1][j],
//	                providerHints[2][k],
//	                ...
//	                providerHints[-1][z]
//	            }
//	            callback(permutation)
//
// 迭代所有提供程序拓扑提示
func iterateAllProviderTopologyHints(allProviderHints [][]TopologyHint, callback func([]TopologyHint)) {
	// Internal helper function to accumulate the permutation before calling the callback.
	var iterate func(i int, accum []TopologyHint)
	iterate = func(i int, accum []TopologyHint) {
		// Base case: we have looped through all providers and have a full permutation.
		if i == len(allProviderHints) {
			callback(accum)
			return
		}

		// Loop through all hints for provider 'i', and recurse to build the
		// permutation of this hint with all hints from providers 'i++'.
		for j := range allProviderHints[i] {
			iterate(i+1, append(accum, allProviderHints[i][j]))
		}
	}
	iterate(0, []TopologyHint{})
}

func filterProvidersHints(providersHints []map[string][]TopologyHint) [][]TopologyHint {
	//这段代码的目的是遍历所有的提示提供者（hintProviders）,并保存每个提示提供者返回的提示（hints）到一个累积的列表（accumulatedHints）中.
	//如果某个提示提供者没有提供任何提示,则假设该提供者对于基于拓扑的分配没有偏好.

	_ = `[
{
	"gpu":[{uint64,bool}],
	"vgpu":[{uint64,bool}]
},
{
	"cpu":[{uint64,bool}]
}
]`

	var allProviderHints [][]TopologyHint
	for _, hints := range providersHints {
		// If hints is nil, insert a single, preferred any-numa hint into allProviderHints.
		if len(hints) == 0 {
			klog.InfoS("提供者对于NUMA亲和性（NUMA affinity）没有任何资源的偏好,那么可以将这种情况视为没有提供任何提示.")
			allProviderHints = append(allProviderHints, []TopologyHint{{nil, true}})
			continue
		}

		// Otherwise, accumulate the hints for each resource type into allProviderHints.
		for resource := range hints {
			if hints[resource] == nil {
				klog.InfoS("Hint Provider has no preference for NUMA affinity with resource", "resource", resource)
				allProviderHints = append(allProviderHints, []TopologyHint{{nil, true}})
				continue
			}

			if len(hints[resource]) == 0 {
				klog.InfoS("Hint Provider has no possible NUMA affinities for resource", "resource", resource)
				allProviderHints = append(allProviderHints, []TopologyHint{{nil, false}})
				continue
			}

			allProviderHints = append(allProviderHints, hints[resource])
		}
	}
	return allProviderHints
}
func narrowestHint(hints []TopologyHint) *TopologyHint { // numa 心数 更少,更接近
	if len(hints) == 0 {
		return nil
	}
	var narrowestHint *TopologyHint
	for i := range hints {
		if hints[i].NUMANodeAffinity == nil {
			continue
		}
		if narrowestHint == nil {
			narrowestHint = &hints[i]
		}
		if hints[i].NUMANodeAffinity.IsNarrowerThan(narrowestHint.NUMANodeAffinity) {
			narrowestHint = &hints[i]
		}
	}
	return narrowestHint
}

func maxOfMinAffinityCounts(filteredHints [][]TopologyHint) int {
	maxOfMinCount := 0
	for _, resourceHints := range filteredHints {
		narrowestHint := narrowestHint(resourceHints)
		if narrowestHint == nil {
			continue
		}
		if narrowestHint.NUMANodeAffinity.Count() > maxOfMinCount {
			maxOfMinCount = narrowestHint.NUMANodeAffinity.Count()
		}
	}
	return maxOfMinCount
}

// 通过对亲和掩码进行按位与操作,将TopologyHints排列合并为单个提示.如果排列中的所有提示都是首选的,则该提示将被优先选择.
func mergePermutation(defaultAffinity bitmask.BitMask, permutation []TopologyHint) TopologyHint {
	preferred := true
	var numaAffinities []bitmask.BitMask
	//  0 1 0 0 0 1 0 0
	//  0 0 1 1 0 0 0 0
	//
	fmt.Println(permutation)
	for _, hint := range permutation {
		// Only consider hints that have an actual NUMANodeAffinity set.
		if hint.NUMANodeAffinity != nil {
			numaAffinities = append(numaAffinities, hint.NUMANodeAffinity)
			// 如果所有亲和性都是首选的,才将其标记为首选.
			if !hint.NUMANodeAffinity.IsEqual(numaAffinities[0]) {
				preferred = false
			}
		}
		// 如果所有亲和性都是首选的,才将其标记为首选.
		if !hint.Preferred {
			preferred = false
		}
	}

	mergedAffinity := bitmask.And(defaultAffinity, numaAffinities...)

	return TopologyHint{mergedAffinity, preferred} // 根据合并的亲和掩码构建一个mergedHint,并根据需要设置首选.

}

func (m HintMerger) Merge() TopologyHint {
	defaultAffinity := m.NUMAInfo.DefaultAffinityMask()

	var bestHint *TopologyHint

	// 迭代所有提供程序拓扑提示
	iterateAllProviderTopologyHints(m.Hints, func(permutation []TopologyHint) {
		mergedHint := mergePermutation(defaultAffinity, permutation)
		bestHint = m.compare(bestHint, &mergedHint)
	})

	if bestHint == nil {
		bestHint = &TopologyHint{defaultAffinity, false}
	}

	return *bestHint
}

func NewHintMerger(numaInfo *NUMAInfo, hints [][]TopologyHint, policyName string, opts PolicyOptions) HintMerger {
	compareNumaAffinityMasks := func(current, candidate *TopologyHint) *TopologyHint {
		// 如果当前位掩码和候选位掩码相同,那么更倾向于选择当前的提示.
		if candidate.NUMANodeAffinity.IsEqual(current.NUMANodeAffinity) {
			return current
		}

		// 根据提供的策略选项比较提示
		var best bitmask.BitMask
		if (policyName != PolicySingleNumaNode) && opts.PreferClosestNUMA {
			best = numaInfo.Closest(current.NUMANodeAffinity, candidate.NUMANodeAffinity)
		} else {
			best = numaInfo.Narrowest(current.NUMANodeAffinity, candidate.NUMANodeAffinity)
		}
		if best.IsEqual(current.NUMANodeAffinity) {
			return current
		}
		return candidate
	}

	merger := HintMerger{
		NUMAInfo:                      numaInfo,
		Hints:                         hints,
		BestNonPreferredAffinityCount: maxOfMinAffinityCounts(hints), // 计算给定提示提供者的最小亲和计数中的最大值
		CompareNUMAAffinityMasks:      compareNumaAffinityMasks,
	}

	return merger
}
