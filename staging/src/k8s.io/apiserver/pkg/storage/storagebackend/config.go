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

package storagebackend

import (
	"time"

	oteltrace "go.opentelemetry.io/otel/trace"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/server/egressselector"
	"k8s.io/apiserver/pkg/storage/etcd3"
	"k8s.io/apiserver/pkg/storage/value"
	flowcontrolrequest "k8s.io/apiserver/pkg/util/flowcontrol/request"
)

const (
	StorageTypeUnset = ""
	StorageTypeETCD2 = "etcd2"
	StorageTypeETCD3 = "etcd3"

	DefaultCompactInterval      = 5 * time.Minute
	DefaultDBMetricPollInterval = 30 * time.Second
	DefaultHealthcheckTimeout   = 2 * time.Second
	DefaultReadinessTimeout     = 2 * time.Second
)

// TransportConfig holds all connection related info,  i.e. equal TransportConfig means equal servers we talk to.
type TransportConfig struct {
	ServerList []string // 要连接的存储服务器的列表.
	// TLS credentials
	KeyFile       string
	CertFile      string
	TrustedCAFile string
	// function to determine the egress dialer. (i.e. konnectivity server dialer)
	EgressLookup egressselector.Lookup
	// The TracerProvider can add tracing the connection
	TracerProvider oteltrace.TracerProvider
}

// Config is configuration for creating a storage backend.
type Config struct {
	Type      string          // 定义了etcd 存储版本, 默认 '' 是etcd3
	Prefix    string          // 定义了存储在etcd的key的前缀
	Transport TransportConfig // 保存所有与连接相关的信息

	// Paging indicates whether the server implementation should allow paging (if it is
	// supported). This is generally configured by feature gating, or by a specific
	// resource type not wishing to allow paging, and is not intended for end users to
	// set.
	Paging bool

	Codec runtime.Codec
	// EncodeVersioner is the same groupVersioner used to build the
	// storage encoder. Given a list of kinds the input object might belong
	// to, the EncodeVersioner outputs the gvk the object will be
	// converted to before persisted in etcd.
	EncodeVersioner runtime.GroupVersioner
	// Transformer allows the value to be transformed prior to persisting into etcd.
	Transformer value.Transformer

	CompactionInterval    time.Duration // etcd数据压缩间隔  5m
	CountMetricPollPeriod time.Duration // 计数指标 1m 更新一次
	DBMetricPollInterval  time.Duration // 30s 指定存储后端指标应该多久更新一次.
	HealthcheckTimeout    time.Duration // 健康检查超时时间 2s
	ReadycheckTimeout     time.Duration // 可用性检查 2s一次

	LeaseManagerConfig        etcd3.LeaseManagerConfig                     // 租约管理
	StorageObjectCountTracker flowcontrolrequest.StorageObjectCountTracker // 用于跟踪每个资源中存储的对象总数.
}

// ConfigForResource is a Config specialized to a particular `schema.GroupResource`
type ConfigForResource struct {
	// Config is the resource-independent configuration
	Config

	// GroupResource is the relevant one
	GroupResource schema.GroupResource
}

// ForResource specializes to the given resource
func (config *Config) ForResource(resource schema.GroupResource) *ConfigForResource {
	return &ConfigForResource{
		Config:        *config,
		GroupResource: resource,
	}
}

func NewDefaultConfig(prefix string, codec runtime.Codec) *Config {
	return &Config{
		Paging:               true,
		Prefix:               prefix,
		Codec:                codec,
		CompactionInterval:   DefaultCompactInterval,
		DBMetricPollInterval: DefaultDBMetricPollInterval,
		HealthcheckTimeout:   DefaultHealthcheckTimeout,
		ReadycheckTimeout:    DefaultReadinessTimeout,
		LeaseManagerConfig:   etcd3.NewDefaultLeaseManagerConfig(),
		Transport:            TransportConfig{TracerProvider: oteltrace.NewNoopTracerProvider()},
	}
}
