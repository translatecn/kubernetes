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

type singleNumaNodePolicy struct {
	// numaInfo represents list of NUMA Nodes available on the underlying machine and distances between them
	numaInfo *NUMAInfo
	opts     PolicyOptions
}

//"restricted"策略会只允许容器在请求资源的最佳NUMA节点上运行.
//"best-effort"策略会优先选择具有CPU和设备资源在NUMA节点上对齐的容器.
//"none"策略表示拓扑管理器不会考虑容器在NUMA节点上的分配情况.
//"single-numa-node"策略会只允许容器在单个NUMA节点上运行.

var _ Policy = &singleNumaNodePolicy{}

// PolicySingleNumaNode policy name.
const PolicySingleNumaNode string = "single-numa-node"

// NewSingleNumaNodePolicy returns single-numa-node policy.
func NewSingleNumaNodePolicy(numaInfo *NUMAInfo, opts PolicyOptions) Policy {
	return &singleNumaNodePolicy{numaInfo: numaInfo, opts: opts}
}

func (p *singleNumaNodePolicy) Name() string {
	return PolicySingleNumaNode
}

func (p *singleNumaNodePolicy) canAdmitPodResult(hint *TopologyHint) bool {
	return hint.Preferred
}

func filterSingleNumaHints(allResourcesHints [][]TopologyHint) [][]TopologyHint {
	_ = `[
{
	"gpu":[{uint64,bool}],
	"vgpu":[{uint64,bool}]
},
{
	"cpu":[{uint64,bool}]
}
]`
	_ = `[
	[{uint64,bool}],
	[{uint64,bool}]
	]`
	var filteredResourcesHints [][]TopologyHint
	for _, oneResourceHints := range allResourcesHints {
		// 针对每一种资源的numa 结构
		var filtered []TopologyHint
		for _, hint := range oneResourceHints {
			if hint.NUMANodeAffinity == nil && hint.Preferred {
				// 每一个资源下  , 每一种符合最小资源需求的 numa 组合,可能用到了多个numa 节点
				filtered = append(filtered, hint)
			}
			if hint.NUMANodeAffinity != nil && hint.NUMANodeAffinity.Count() == 1 && hint.Preferred {
				// 每一个资源下  , 每一种符合最小资源需求的 numa 组合,只用到了一个numa 节点
				filtered = append(filtered, hint)
			}
		}
		filteredResourcesHints = append(filteredResourcesHints, filtered)
	}
	return filteredResourcesHints
}

func (p *singleNumaNodePolicy) Merge(providersHints []map[string][]TopologyHint) (TopologyHint, bool) {
	filteredHints := filterProvidersHints(providersHints) // ✅
	// 将只包括一个NUMA节点的不关心和提示筛选出来.
	singleNumaHints := filterSingleNumaHints(filteredHints)

	merger := NewHintMerger(p.numaInfo, singleNumaHints, p.Name(), p.opts)
	bestHint := merger.Merge()

	if bestHint.NUMANodeAffinity.IsEqual(p.numaInfo.DefaultAffinityMask()) {
		bestHint = TopologyHint{nil, bestHint.Preferred}
	}

	admit := p.canAdmitPodResult(&bestHint)
	return bestHint, admit
}
