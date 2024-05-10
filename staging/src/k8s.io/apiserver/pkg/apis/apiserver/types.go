/*
Copyright 2017 The Kubernetes Authors.

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

package apiserver

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AdmissionConfiguration 提供允许控制器的版本配置.
type AdmissionConfiguration struct {
	metav1.TypeMeta
	// Plugins 允许为每个准入控制插件指定一个配置
	// +optional
	Plugins []AdmissionPluginConfiguration
}

// AdmissionPluginConfiguration 提供单个插件的配置.
type AdmissionPluginConfiguration struct {
	// Name 准入控制器的名称.它必须与注册的许可插件名称匹配.
	Name string

	// Path 是包含插件配置的配置文件的路径
	// +optional
	Path string

	// Configuration is an embedded configuration object to be used as the plugin's
	// configuration. If present, it will be used instead of the path to the configuration file.
	// +optional
	Configuration *runtime.Unknown
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// EgressSelectorConfiguration provides versioned configuration for egress selector clients.
type EgressSelectorConfiguration struct {
	metav1.TypeMeta

	// EgressSelections contains a list of egress selection client configurations
	EgressSelections []EgressSelection
}

// EgressSelection provides the configuration for a single egress selection client.
type EgressSelection struct {
	Name       string     // 目前支持的值为controlplane、etcd和cluster.
	Connection Connection // 用于配置Egress的确切信息
}

// Connection provides the configuration for a single egress selection client.
type Connection struct {
	ProxyProtocol ProtocolType // 协议是用于从客户端连接到连接服务器的协议.
	Transport     *Transport   // 定义用于拨号到连接服务器的传输配置.如果ProxyProtocol是HTTPConnect或GRPC,这是必需的.

}

type ProtocolType string

// https://blog.csdn.net/xiaoyi52/article/details/125028052
// 链接到 konnectivity 服务器的协议方式
const (
	ProtocolHTTPConnect ProtocolType = "HTTPConnect"
	ProtocolGRPC        ProtocolType = "GRPC"
	ProtocolDirect      ProtocolType = "Direct"
)

// Transport defines the transport configurations we use to dial to the konnectivity server
type Transport struct {
	// TCP is the TCP configuration for communicating with the konnectivity server via TCP
	// ProxyProtocol of GRPC is not supported with TCP transport at the moment
	// Requires at least one of TCP or UDS to be set
	// +optional
	TCP *TCPTransport

	// UDS is the UDS configuration for communicating with the konnectivity server via UDS
	// Requires at least one of TCP or UDS to be set
	// +optional
	UDS *UDSTransport
}

// TCPTransport provides the information to connect to konnectivity server via TCP
type TCPTransport struct {
	// URL is the location of the konnectivity server to connect to.
	// As an example it might be "https://127.0.0.1:8131"
	URL string

	// TLSConfig is the config needed to use TLS when connecting to konnectivity server
	// +optional
	TLSConfig *TLSConfig
}

// UDSTransport provides the information to connect to konnectivity server via UDS
type UDSTransport struct {
	// UDSName is the name of the unix domain socket to connect to konnectivity server
	// This does not use a unix:// prefix. (Eg: /etc/srv/kubernetes/konnectivity-server/konnectivity-server.socket)
	UDSName string
}

// TLSConfig provides the authentication information to connect to konnectivity server
// Only used with TCPTransport
type TLSConfig struct {
	// caBundle is the file location of the CA to be used to determine trust with the konnectivity server.
	// Must be absent/empty if TCPTransport.URL is prefixed with http://
	// If absent while TCPTransport.URL is prefixed with https://, default to system trust roots.
	// +optional
	CABundle string

	// clientKey is the file location of the client key to authenticate with the konnectivity server
	// Must be absent/empty if TCPTransport.URL is prefixed with http://
	// Must be configured if TCPTransport.URL is prefixed with https://
	// +optional
	ClientKey string

	// clientCert is the file location of the client certificate to authenticate with the konnectivity server
	// Must be absent/empty if TCPTransport.URL is prefixed with http://
	// Must be configured if TCPTransport.URL is prefixed with https://
	// +optional
	ClientCert string
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TracingConfiguration provides versioned configuration for tracing clients.
type TracingConfiguration struct {
	metav1.TypeMeta

	// +optional
	// Endpoint of the collector that's running on the control-plane node.
	// The APIServer uses the egressType ControlPlane when sending data to the collector.
	// The syntax is defined in https://github.com/grpc/grpc/blob/master/doc/naming.md.
	// Defaults to the otlp grpc default, localhost:4317
	// The connection is insecure, and does not currently support TLS.
	Endpoint *string

	// +optional
	// SamplingRatePerMillion is the number of samples to collect per million spans.
	// Defaults to 0.
	SamplingRatePerMillion *int32
}
