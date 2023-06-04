//go:build !providerless
// +build !providerless

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

package app

import (
	"k8s.io/component-base/featuregate"
	"k8s.io/csi-translation-lib/plugins"
	"k8s.io/klog/v2"
	// Credential providers
	_ "k8s.io/kubernetes/pkg/credentialprovider/aws"
	_ "k8s.io/kubernetes/pkg/credentialprovider/azure"
	_ "k8s.io/kubernetes/pkg/credentialprovider/gcp"
	"k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/pkg/volume"
	"k8s.io/kubernetes/pkg/volume/csimigration"
	"k8s.io/kubernetes/pkg/volume/portworx"
)

type probeFn func() []volume.VolumePlugin

func appendPluginBasedOnFeatureFlags(plugins []volume.VolumePlugin, inTreePluginName string,
	featureGate featuregate.FeatureGate, pluginInfo pluginInfo) ([]volume.VolumePlugin, error) {
	_, err := csimigration.CheckMigrationFeatureFlags(featureGate, pluginInfo.pluginMigrationFeature, pluginInfo.pluginUnregisterFeature)
	if err != nil {
		klog.InfoS("检测到意外的CSI Migration功能标志组合,CSI Migration可能不会生效.", "err", err)
		// TODO: fail and return here once alpha only tests can set the feature flags for a plugin correctly
	}

	// Skip appending the in-tree plugin to the list of plugins to be probed/initialized
	// if the plugin unregister feature flag is set
	if featureGate.Enabled(pluginInfo.pluginUnregisterFeature) {
		klog.InfoS("Skipped registration of plugin since feature flag is enabled", "pluginName", inTreePluginName, "featureFlag", pluginInfo.pluginUnregisterFeature)
		return plugins, nil
	}

	plugins = append(plugins, pluginInfo.pluginProbeFunction()...)
	return plugins, nil
}

type pluginInfo struct {
	pluginMigrationFeature  featuregate.Feature // 表示插件的CSI Migration功能标志.
	pluginUnregisterFeature featuregate.Feature // 表示插件的CSI注销功能标志.
	pluginProbeFunction     probeFn             // 检测插件是否可用
}

func appendLegacyProviderVolumes(allPlugins []volume.VolumePlugin, featureGate featuregate.FeatureGate) ([]volume.VolumePlugin, error) {
	pluginMigrationStatus := make(map[string]pluginInfo)
	pluginMigrationStatus[plugins.PortworxVolumePluginName] = pluginInfo{pluginMigrationFeature: features.CSIMigrationPortworx, pluginUnregisterFeature: features.InTreePluginPortworxUnregister, pluginProbeFunction: portworx.ProbeVolumePlugins}
	var err error
	for pluginName, pluginInfo := range pluginMigrationStatus {
		allPlugins, err = appendPluginBasedOnFeatureFlags(allPlugins, pluginName, featureGate, pluginInfo)
		if err != nil {
			return allPlugins, err
		}
	}
	return allPlugins, nil
}
