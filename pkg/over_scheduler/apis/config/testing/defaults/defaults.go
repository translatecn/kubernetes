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

package defaults

import (
	"k8s.io/kubernetes/pkg/over_scheduler/apis/config"
	"k8s.io/kubernetes/pkg/over_scheduler/framework/plugins/names"
)

// PluginsV1beta2 default set of v1beta2 plugins.
var PluginsV1beta2 = &config.Plugins{
	QueueSort: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.PrioritySort},
		},
	},
	PreFilter: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.NodeResourcesFit},
			{Name: over_names.NodePorts},
			{Name: over_names.VolumeRestrictions},
			{Name: over_names.PodTopologySpread},
			{Name: over_names.InterPodAffinity},
			{Name: over_names.VolumeBinding},
			{Name: over_names.NodeAffinity},
		},
	},
	Filter: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.NodeUnschedulable},
			{Name: over_names.NodeName},
			{Name: over_names.TaintToleration},
			{Name: over_names.NodeAffinity},
			{Name: over_names.NodePorts},
			{Name: over_names.NodeResourcesFit},
			{Name: over_names.VolumeRestrictions},
			{Name: over_names.EBSLimits},
			{Name: over_names.GCEPDLimits},
			{Name: over_names.NodeVolumeLimits},
			{Name: over_names.AzureDiskLimits},
			{Name: over_names.VolumeBinding},
			{Name: over_names.VolumeZone},
			{Name: over_names.PodTopologySpread},
			{Name: over_names.InterPodAffinity},
		},
	},
	PostFilter: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.DefaultPreemption},
		},
	},
	PreScore: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.InterPodAffinity},
			{Name: over_names.PodTopologySpread},
			{Name: over_names.TaintToleration},
			{Name: over_names.NodeAffinity},
		},
	},
	Score: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.NodeResourcesBalancedAllocation, Weight: 1},
			{Name: over_names.ImageLocality, Weight: 1},
			{Name: over_names.InterPodAffinity, Weight: 1},
			{Name: over_names.NodeResourcesFit, Weight: 1},
			{Name: over_names.NodeAffinity, Weight: 1},
			// Weight is doubled because:
			// - This is a score coming from user preference.
			// - It makes its signal comparable to NodeResourcesLeastAllocated.
			{Name: over_names.PodTopologySpread, Weight: 2},
			{Name: over_names.TaintToleration, Weight: 1},
		},
	},
	Reserve: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.VolumeBinding},
		},
	},
	PreBind: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.VolumeBinding},
		},
	},
	Bind: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.DefaultBinder},
		},
	},
}

// PluginConfigsV1beta2 default plugin configurations. This could get versioned, but since
// all available versions produce the same defaults, we just have one for now.
var PluginConfigsV1beta2 = []config.PluginConfig{
	{
		Name: "DefaultPreemption",
		Args: &config.DefaultPreemptionArgs{
			MinCandidateNodesPercentage: 10,
			MinCandidateNodesAbsolute:   100,
		},
	},
	{
		Name: "InterPodAffinity",
		Args: &config.InterPodAffinityArgs{
			HardPodAffinityWeight: 1,
		},
	},
	{
		Name: "NodeAffinity",
		Args: &config.NodeAffinityArgs{},
	},
	{
		Name: "NodeResourcesBalancedAllocation",
		Args: &config.NodeResourcesBalancedAllocationArgs{
			Resources: []config.ResourceSpec{{Name: "cpu", Weight: 1}, {Name: "memory", Weight: 1}},
		},
	},
	{
		Name: "NodeResourcesFit",
		Args: &config.NodeResourcesFitArgs{
			ScoringStrategy: &config.ScoringStrategy{
				Type:      config.LeastAllocated,
				Resources: []config.ResourceSpec{{Name: "cpu", Weight: 1}, {Name: "memory", Weight: 1}},
			},
		},
	},
	{
		Name: "PodTopologySpread",
		Args: &config.PodTopologySpreadArgs{
			DefaultingType: config.SystemDefaulting,
		},
	},
	{
		Name: "VolumeBinding",
		Args: &config.VolumeBindingArgs{
			BindTimeoutSeconds: 600,
		},
	},
}

// PluginsV1beta3 is the set of default v1beta3 plugins (before MultiPoint expansion)
var PluginsV1beta3 = &config.Plugins{
	MultiPoint: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.PrioritySort},
			{Name: over_names.NodeUnschedulable},
			{Name: over_names.NodeName},
			{Name: over_names.TaintToleration, Weight: 3},
			{Name: over_names.NodeAffinity, Weight: 2},
			{Name: over_names.NodePorts},
			{Name: over_names.NodeResourcesFit, Weight: 1},
			{Name: over_names.VolumeRestrictions},
			{Name: over_names.EBSLimits},
			{Name: over_names.GCEPDLimits},
			{Name: over_names.NodeVolumeLimits},
			{Name: over_names.AzureDiskLimits},
			{Name: over_names.VolumeBinding},
			{Name: over_names.VolumeZone},
			{Name: over_names.PodTopologySpread, Weight: 2},
			{Name: over_names.InterPodAffinity, Weight: 2},
			{Name: over_names.DefaultPreemption},
			{Name: over_names.NodeResourcesBalancedAllocation, Weight: 1},
			{Name: over_names.ImageLocality, Weight: 1},
			{Name: over_names.DefaultBinder},
		},
	},
}

// ExpandedPluginsV1beta3 default set of v1beta3 plugins after MultiPoint expansion
var ExpandedPluginsV1beta3 = &config.Plugins{
	QueueSort: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.PrioritySort},
		},
	},
	PreFilter: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.NodeAffinity},
			{Name: over_names.NodePorts},
			{Name: over_names.NodeResourcesFit},
			{Name: over_names.VolumeRestrictions},
			{Name: over_names.VolumeBinding},
			{Name: over_names.PodTopologySpread},
			{Name: over_names.InterPodAffinity},
		},
	},
	Filter: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.NodeUnschedulable},
			{Name: over_names.NodeName},
			{Name: over_names.TaintToleration},
			{Name: over_names.NodeAffinity},
			{Name: over_names.NodePorts},
			{Name: over_names.NodeResourcesFit},
			{Name: over_names.VolumeRestrictions},
			{Name: over_names.EBSLimits},
			{Name: over_names.GCEPDLimits},
			{Name: over_names.NodeVolumeLimits},
			{Name: over_names.AzureDiskLimits},
			{Name: over_names.VolumeBinding},
			{Name: over_names.VolumeZone},
			{Name: over_names.PodTopologySpread},
			{Name: over_names.InterPodAffinity},
		},
	},
	PostFilter: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.DefaultPreemption},
		},
	},
	PreScore: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.TaintToleration},
			{Name: over_names.NodeAffinity},
			{Name: over_names.PodTopologySpread},
			{Name: over_names.InterPodAffinity},
		},
	},
	Score: config.PluginSet{
		Enabled: []config.Plugin{
			// Weight is tripled because:
			// - This is a score coming from user preference.
			// - Usage of node tainting to group nodes in the cluster is increasing becoming a use-case
			// for many user workloads
			{Name: over_names.TaintToleration, Weight: 3},
			// Weight is doubled because:
			// - This is a score coming from user preference.
			{Name: over_names.NodeAffinity, Weight: 2},
			{Name: over_names.NodeResourcesFit, Weight: 1},
			// Weight is tripled because:
			// - This is a score coming from user preference.
			// - Usage of node tainting to group nodes in the cluster is increasing becoming a use-case
			//	 for many user workloads
			{Name: over_names.VolumeBinding, Weight: 1},
			// Weight is doubled because:
			// - This is a score coming from user preference.
			// - It makes its signal comparable to NodeResourcesLeastAllocated.
			{Name: over_names.PodTopologySpread, Weight: 2},
			// Weight is doubled because:
			// - This is a score coming from user preference.
			{Name: over_names.InterPodAffinity, Weight: 2},
			{Name: over_names.NodeResourcesBalancedAllocation, Weight: 1},
			{Name: over_names.ImageLocality, Weight: 1},
		},
	},
	Reserve: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.VolumeBinding},
		},
	},
	PreBind: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.VolumeBinding},
		},
	},
	Bind: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.DefaultBinder},
		},
	},
}

// PluginConfigsV1beta3 default plugin configurations.
var PluginConfigsV1beta3 = []config.PluginConfig{
	{
		Name: "DefaultPreemption",
		Args: &config.DefaultPreemptionArgs{
			MinCandidateNodesPercentage: 10,
			MinCandidateNodesAbsolute:   100,
		},
	},
	{
		Name: "InterPodAffinity",
		Args: &config.InterPodAffinityArgs{
			HardPodAffinityWeight: 1,
		},
	},
	{
		Name: "NodeAffinity",
		Args: &config.NodeAffinityArgs{},
	},
	{
		Name: "NodeResourcesBalancedAllocation",
		Args: &config.NodeResourcesBalancedAllocationArgs{
			Resources: []config.ResourceSpec{{Name: "cpu", Weight: 1}, {Name: "memory", Weight: 1}},
		},
	},
	{
		Name: "NodeResourcesFit",
		Args: &config.NodeResourcesFitArgs{
			ScoringStrategy: &config.ScoringStrategy{
				Type:      config.LeastAllocated,
				Resources: []config.ResourceSpec{{Name: "cpu", Weight: 1}, {Name: "memory", Weight: 1}},
			},
		},
	},
	{
		Name: "PodTopologySpread",
		Args: &config.PodTopologySpreadArgs{
			DefaultingType: config.SystemDefaulting,
		},
	},
	{
		Name: "VolumeBinding",
		Args: &config.VolumeBindingArgs{
			BindTimeoutSeconds: 600,
		},
	},
}

// PluginsV1 is the set of default v1 plugins (before MultiPoint expansion)
var PluginsV1 = &config.Plugins{
	MultiPoint: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.PrioritySort},
			{Name: over_names.NodeUnschedulable},
			{Name: over_names.NodeName},
			{Name: over_names.TaintToleration, Weight: 3},
			{Name: over_names.NodeAffinity, Weight: 2},
			{Name: over_names.NodePorts},
			{Name: over_names.NodeResourcesFit, Weight: 1},
			{Name: over_names.VolumeRestrictions},
			{Name: over_names.EBSLimits},
			{Name: over_names.GCEPDLimits},
			{Name: over_names.NodeVolumeLimits},
			{Name: over_names.AzureDiskLimits},
			{Name: over_names.VolumeBinding},
			{Name: over_names.VolumeZone},
			{Name: over_names.PodTopologySpread, Weight: 2},
			{Name: over_names.InterPodAffinity, Weight: 2},
			{Name: over_names.DefaultPreemption},
			{Name: over_names.NodeResourcesBalancedAllocation, Weight: 1},
			{Name: over_names.ImageLocality, Weight: 1},
			{Name: over_names.DefaultBinder},
		},
	},
}

// ExpandedPluginsV1 default set of v1 plugins after MultiPoint expansion
var ExpandedPluginsV1 = &config.Plugins{
	QueueSort: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.PrioritySort},
		},
	},
	PreFilter: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.NodeAffinity},
			{Name: over_names.NodePorts},
			{Name: over_names.NodeResourcesFit},
			{Name: over_names.VolumeRestrictions},
			{Name: over_names.VolumeBinding},
			{Name: over_names.PodTopologySpread},
			{Name: over_names.InterPodAffinity},
		},
	},
	Filter: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.NodeUnschedulable},
			{Name: over_names.NodeName},
			{Name: over_names.TaintToleration},
			{Name: over_names.NodeAffinity},
			{Name: over_names.NodePorts},
			{Name: over_names.NodeResourcesFit},
			{Name: over_names.VolumeRestrictions},
			{Name: over_names.EBSLimits},
			{Name: over_names.GCEPDLimits},
			{Name: over_names.NodeVolumeLimits},
			{Name: over_names.AzureDiskLimits},
			{Name: over_names.VolumeBinding},
			{Name: over_names.VolumeZone},
			{Name: over_names.PodTopologySpread},
			{Name: over_names.InterPodAffinity},
		},
	},
	PostFilter: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.DefaultPreemption},
		},
	},
	PreScore: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.TaintToleration},
			{Name: over_names.NodeAffinity},
			{Name: over_names.PodTopologySpread},
			{Name: over_names.InterPodAffinity},
		},
	},
	Score: config.PluginSet{
		Enabled: []config.Plugin{
			// Weight is tripled because:
			// - This is a score coming from user preference.
			// - Usage of node tainting to group nodes in the cluster is increasing becoming a use-case
			// for many user workloads
			{Name: over_names.TaintToleration, Weight: 3},
			// Weight is doubled because:
			// - This is a score coming from user preference.
			{Name: over_names.NodeAffinity, Weight: 2},
			{Name: over_names.NodeResourcesFit, Weight: 1},
			// Weight is tripled because:
			// - This is a score coming from user preference.
			// - Usage of node tainting to group nodes in the cluster is increasing becoming a use-case
			//	 for many user workloads
			{Name: over_names.VolumeBinding, Weight: 1},
			// Weight is doubled because:
			// - This is a score coming from user preference.
			// - It makes its signal comparable to NodeResourcesLeastAllocated.
			{Name: over_names.PodTopologySpread, Weight: 2},
			// Weight is doubled because:
			// - This is a score coming from user preference.
			{Name: over_names.InterPodAffinity, Weight: 2},
			{Name: over_names.NodeResourcesBalancedAllocation, Weight: 1},
			{Name: over_names.ImageLocality, Weight: 1},
		},
	},
	Reserve: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.VolumeBinding},
		},
	},
	PreBind: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.VolumeBinding},
		},
	},
	Bind: config.PluginSet{
		Enabled: []config.Plugin{
			{Name: over_names.DefaultBinder},
		},
	},
}

// PluginConfigsV1 default plugin configurations.
var PluginConfigsV1 = []config.PluginConfig{
	{
		Name: "DefaultPreemption",
		Args: &config.DefaultPreemptionArgs{
			MinCandidateNodesPercentage: 10,
			MinCandidateNodesAbsolute:   100,
		},
	},
	{
		Name: "InterPodAffinity",
		Args: &config.InterPodAffinityArgs{
			HardPodAffinityWeight: 1,
		},
	},
	{
		Name: "NodeAffinity",
		Args: &config.NodeAffinityArgs{},
	},
	{
		Name: "NodeResourcesBalancedAllocation",
		Args: &config.NodeResourcesBalancedAllocationArgs{
			Resources: []config.ResourceSpec{{Name: "cpu", Weight: 1}, {Name: "memory", Weight: 1}},
		},
	},
	{
		Name: "NodeResourcesFit",
		Args: &config.NodeResourcesFitArgs{
			ScoringStrategy: &config.ScoringStrategy{
				Type:      config.LeastAllocated,
				Resources: []config.ResourceSpec{{Name: "cpu", Weight: 1}, {Name: "memory", Weight: 1}},
			},
		},
	},
	{
		Name: "PodTopologySpread",
		Args: &config.PodTopologySpreadArgs{
			DefaultingType: config.SystemDefaulting,
		},
	},
	{
		Name: "VolumeBinding",
		Args: &config.VolumeBindingArgs{
			BindTimeoutSeconds: 600,
		},
	},
}
