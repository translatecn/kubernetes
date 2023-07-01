/*
Copyright 2021 The Kubernetes Authors.

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
	"k8s.io/apimachinery/pkg/util/sets"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	kubefeatures "k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpumanager/topology"
	"k8s.io/kubernetes/pkg/kubelet/cm/topologymanager"
	"strconv"
)

const (
	FullPCPUsOnlyOption            string = "full-pcpus-only"             // 将 CPU 管理器核心分配算法限制为仅支持完整的物理核心,从而减少允许共享核心的硬件技术带来的嘈杂邻居问题.
	DistributeCPUsAcrossNUMAOption string = "distribute-cpus-across-numa" // 驱动 CPU 管理器跨 NUMA 节点均匀分配 CPU,以应对需要多个 NUMA 节点来满足分配的情况.
	AlignBySocketOption            string = "align-by-socket"             // 更改 CPU 管理器将 CPU 分配给容器的方式：考虑 CPU 按插槽而不是 NUMA 节点边界对齐.
)

var (
	alphaOptions = sets.NewString(
		DistributeCPUsAcrossNUMAOption,
		AlignBySocketOption,
	)
	betaOptions = sets.NewString(
		FullPCPUsOnlyOption,
	)
	stableOptions = sets.NewString()
)

// CheckPolicyOptionAvailable verifies if the given option can be used depending on the Feature Gate Settings.
// returns nil on success, or an error describing the failure on error.
func CheckPolicyOptionAvailable(option string) error {
	if !alphaOptions.Has(option) && !betaOptions.Has(option) && !stableOptions.Has(option) {
		return fmt.Errorf("unknown CPU Manager Policy option: %q", option)
	}

	if alphaOptions.Has(option) && !utilfeature.DefaultFeatureGate.Enabled(kubefeatures.CPUManagerPolicyAlphaOptions) {
		return fmt.Errorf("CPU Manager Policy Alpha-level Options not enabled, but option %q provided", option)
	}

	if betaOptions.Has(option) && !utilfeature.DefaultFeatureGate.Enabled(kubefeatures.CPUManagerPolicyBetaOptions) {
		return fmt.Errorf("CPU Manager Policy Beta-level Options not enabled, but option %q provided", option)
	}

	return nil
}

type StaticPolicyOptions struct {
	FullPhysicalCPUsOnly     bool
	DistributeCPUsAcrossNUMA bool
	AlignBySocket            bool
}

func ValidateStaticPolicyOptions(opts StaticPolicyOptions, topology *topology.CPUTopology, topologyManager topologymanager.Store) error {
	if opts.AlignBySocket {
		if topologyManager.GetPolicy().Name() == topologymanager.PolicySingleNumaNode {
			return fmt.Errorf("拓扑 CPU 管理器的策略:%s 与 CPU 管理器策略:%s 选项不兼容", topologymanager.PolicySingleNumaNode, AlignBySocketOption)
		}
		if topology.NumSockets > topology.NumNUMANodes {
			return fmt.Errorf("如果硬件的插槽数量超过了NUMA（非一致性存储访问）的数量,那么按插槽对齐是不兼容的, 有的位置m")
		}
	}
	return nil
}

func NewStaticPolicyOptions(policyOptions map[string]string) (StaticPolicyOptions, error) {
	opts := StaticPolicyOptions{}
	for name, value := range policyOptions {
		if err := CheckPolicyOptionAvailable(name); err != nil {
			return opts, err
		}

		switch name {
		case FullPCPUsOnlyOption:
			optValue, err := strconv.ParseBool(value)
			if err != nil {
				return opts, fmt.Errorf("bad value for option %q: %w", name, err)
			}
			opts.FullPhysicalCPUsOnly = optValue
		case DistributeCPUsAcrossNUMAOption:
			optValue, err := strconv.ParseBool(value)
			if err != nil {
				return opts, fmt.Errorf("bad value for option %q: %w", name, err)
			}
			opts.DistributeCPUsAcrossNUMA = optValue
		case AlignBySocketOption:
			optValue, err := strconv.ParseBool(value)
			if err != nil {
				return opts, fmt.Errorf("bad value for option %q: %w", name, err)
			}
			opts.AlignBySocket = optValue
		default:
			// this should never be reached, we already detect unknown options,
			// but we keep it as further safety.
			return opts, fmt.Errorf("unsupported cpumanager option: %q (%s)", name, value)
		}
	}
	return opts, nil
}
