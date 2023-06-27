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

// TracingConfiguration 为OpenTelemetry跟踪客户端提供版本化配置.
type TracingConfiguration struct {
	Endpoint               *string `json:"endpoint,omitempty"`               // 报告跟踪的收集器的端点.该连接不安全,目前不支持TLS.“建议”未设置,端点为otlp grpc默认值,localhost:4317.
	SamplingRatePerMillion *int32  `json:"samplingRatePerMillion,omitempty"` // 每百万span收集的样本数.建议不设置.如果未设置,则采样器尊重其父 span 的采样率,否则从不采样.
}
