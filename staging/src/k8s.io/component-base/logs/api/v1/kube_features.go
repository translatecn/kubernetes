/*
Copyright 2022 The Kubernetes Authors.

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

package v1

import (
	"k8s.io/component-base/featuregate"
)

const (
	// ContextualLogging alpha: v1.24
	ContextualLogging        featuregate.Feature = "ContextualLogging"    // 允许从上下文中查找记录器，而不是使用全局回退记录器和操作调用链使用的记录器。
	contextualLoggingDefault                     = false                  // contextualLoggingDefault 在alpha中必须保持false。它可以在测试中成为true
	LoggingAlphaOptions      featuregate.Feature = "LoggingAlphaOptions"  // 记录Alpha日志
	LoggingBetaOptions       featuregate.Feature = "LoggingBetaOptions"   // 记录Beta日志
	LoggingStableOptions     featuregate.Feature = "LoggingStableOptions" // 稳定的日志选项。总是启用。
)

func featureGates() map[featuregate.Feature]featuregate.FeatureSpec {
	return map[featuregate.Feature]featuregate.FeatureSpec{
		ContextualLogging: {Default: contextualLoggingDefault, PreRelease: featuregate.Alpha},

		LoggingAlphaOptions: {Default: false, PreRelease: featuregate.Alpha},
		LoggingBetaOptions:  {Default: true, PreRelease: featuregate.Beta},
	}
}

// AddFeatureGates adds all feature gates used by this package.
func AddFeatureGates(mutableFeatureGate featuregate.MutableFeatureGate) error {
	return mutableFeatureGate.Add(featureGates())
}
