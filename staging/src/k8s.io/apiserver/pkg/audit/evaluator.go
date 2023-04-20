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

package audit

import (
	"k8s.io/apiserver/pkg/apis/audit"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

// RequestAuditConfig 是适用于给定请求的评估审计配置.
// PolicyRuleEvaluator 根据授权器属性评估审计策略,并返回适用于请求的RequestAuditConfig.
type RequestAuditConfig struct {
	OmitStages        []audit.Stage // 这些阶段需要从审计中省略.
	OmitManagedFields bool          // 指示是否省略请求和响应正文的托管字段,以便不将其写入API审计日志中.
}

type RequestAuditConfigWithLevel struct {
	RequestAuditConfig
	Level audit.Level
}

// PolicyRuleEvaluator exposes methods for evaluating the policy rules.
type PolicyRuleEvaluator interface {
	// EvaluatePolicyRule 评估apiserver的审计策略,根据给定的授权器属性返回适用于给定请求的审计配置.
	EvaluatePolicyRule(authorizer.Attributes) RequestAuditConfigWithLevel
}
