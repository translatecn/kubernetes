/*
Copyright 2016 The Kubernetes Authors.

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

package admission

import (
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/admission/initializer"
	quota "k8s.io/apiserver/pkg/quota/v1"
)

// TODO add a `WantsToRun` which takes a stopCh.  Might make it generic.

// WantsCloudConfig 定义了一个函数,该函数为需要CloudConfig的准入插件设置CloudConfig.
type WantsCloudConfig interface {
	SetCloudConfig([]byte)
}

// PluginInitializer 用于初始化Kubernetes特定的准入插件.
type PluginInitializer struct {
	cloudConfig        []byte
	restMapper         meta.RESTMapper
	quotaConfiguration quota.Configuration
}

var _ admission.PluginInitializer = &PluginInitializer{}

func NewPluginInitializer(
	cloudConfig []byte,
	restMapper meta.RESTMapper,
	quotaConfiguration quota.Configuration,
) *PluginInitializer {
	return &PluginInitializer{
		cloudConfig:        cloudConfig,
		restMapper:         restMapper,
		quotaConfiguration: quotaConfiguration,
	}
}

func (i *PluginInitializer) Initialize(plugin admission.Interface) {
	if wants, ok := plugin.(WantsCloudConfig); ok {
		wants.SetCloudConfig(i.cloudConfig)
	}

	if wants, ok := plugin.(initializer.WantsRESTMapper); ok {
		wants.SetRESTMapper(i.restMapper)
	}

	if wants, ok := plugin.(initializer.WantsQuotaConfiguration); ok {
		wants.SetQuotaConfiguration(i.quotaConfiguration)
	}
}
