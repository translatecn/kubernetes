/*
Copyright 2020 The Kubernetes Authors.

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

package serviceaccount

import (
	"sync"

	"k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
)

const kubeServiceAccountSubsystem = "serviceaccount"

var (
	legacyTokensTotal = metrics.NewCounter(
		&metrics.CounterOpts{
			Subsystem:      kubeServiceAccountSubsystem,
			Name:           "legacy_tokens_total",
			Help:           "累计使用的遗留服务账户令牌数",
			StabilityLevel: metrics.ALPHA,
		},
	)

	staleTokensTotal = metrics.NewCounter(
		&metrics.CounterOpts{
			Subsystem:      kubeServiceAccountSubsystem,
			Name:           "stale_tokens_total",
			Help:           "所使用的累计过期服务帐户令牌",
			StabilityLevel: metrics.ALPHA,
		},
	)

	validTokensTotal = metrics.NewCounter(
		&metrics.CounterOpts{
			Subsystem:      kubeServiceAccountSubsystem,
			Name:           "valid_tokens_total",
			Help:           "使用过的的有效sa令牌的数量",
			StabilityLevel: metrics.ALPHA,
		},
	)
)

var registerMetricsOnce sync.Once

func RegisterMetrics() {
	registerMetricsOnce.Do(func() {
		legacyregistry.MustRegister(legacyTokensTotal)
		legacyregistry.MustRegister(staleTokensTotal)
		legacyregistry.MustRegister(validTokensTotal)
	})
}
