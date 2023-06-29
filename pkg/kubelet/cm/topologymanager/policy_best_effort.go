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

type bestEffortPolicy struct {
	numaInfo *NUMAInfo
	opts     PolicyOptions
}

var _ Policy = &bestEffortPolicy{}

//"restricted"策略会只允许容器在请求资源的最佳NUMA节点上运行.
//"best-effort"策略会优先选择具有CPU和设备资源在NUMA节点上对齐的容器.
//"none"策略表示拓扑管理器不会考虑容器在NUMA节点上的分配情况.
//"single-numa-node"策略会只允许容器在单个NUMA节点上运行.

const PolicyBestEffort string = "best-effort"

func NewBestEffortPolicy(numaInfo *NUMAInfo, opts PolicyOptions) Policy {
	return &bestEffortPolicy{numaInfo: numaInfo, opts: opts}
}

func (p *bestEffortPolicy) Name() string {
	return PolicyBestEffort
}

func (p *bestEffortPolicy) canAdmitPodResult(hint *TopologyHint) bool {
	return true
}

func (p *bestEffortPolicy) Merge(providersHints []map[string][]TopologyHint) (TopologyHint, bool) {
	_ = `[
{
	"gpu":[{uint64,bool}],
	"vgpu":[{uint64,bool}]
},
{
	"cpu":[{uint64,bool}]
}
]`
	filteredHints := filterProvidersHints(providersHints)
	merger := NewHintMerger(p.numaInfo, filteredHints, p.Name(), p.opts)
	bestHint := merger.Merge()
	admit := p.canAdmitPodResult(&bestHint)
	return bestHint, admit
}
