/*
Copyright 2014 The Kubernetes Authors.

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

// Package options contains flags and options for initializing an apiserver
package options

import (
	"net"
	"strings"
	"time"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/apiserver/pkg/storage/storagebackend"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/logs"
	"k8s.io/component-base/metrics"

	logsapi "k8s.io/component-base/logs/api/v1"
	api "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/cluster/ports"
	"k8s.io/kubernetes/pkg/controlplane/reconcilers"
	_ "k8s.io/kubernetes/pkg/features" // add the kubernetes feature gates
	kubeoptions "k8s.io/kubernetes/pkg/kubeapiserver/options"
	kubeletclient "k8s.io/kubernetes/pkg/kubelet/client"
	"k8s.io/kubernetes/pkg/serviceaccount"
)

// ServerRunOptions runs a kubernetes api server.
type ServerRunOptions struct {
	GenericServerRunOptions             *genericoptions.ServerRunOptions
	Etcd                                *genericoptions.EtcdOptions
	SecureServing                       *genericoptions.SecureServingOptionsWithLoopback
	Audit                               *genericoptions.AuditOptions
	Features                            *genericoptions.FeatureOptions
	Admission                           *kubeoptions.AdmissionOptions
	Authentication                      *kubeoptions.BuiltInAuthenticationOptions // 认证
	Authorization                       *kubeoptions.BuiltInAuthorizationOptions  // 授权
	CloudProvider                       *kubeoptions.CloudProviderOptions
	APIEnablement                       *genericoptions.APIEnablementOptions
	EgressSelector                      *genericoptions.EgressSelectorOptions
	Metrics                             *metrics.Options
	Logs                                *logs.Options
	Traces                              *genericoptions.TracingOptions
	AllowPrivileged                     bool
	EnableLogsHandler                   bool
	EventTTL                            time.Duration
	KubeletConfig                       kubeletclient.KubeletClientConfig
	KubernetesServiceNodePort           int
	MaxConnectionBytesPerSec            int64
	ServiceClusterIPRanges              string    // 是否映射到用户提供的输入
	PrimaryServiceClusterIPRange        net.IPNet // 集群IP范围 主CIDR
	SecondaryServiceClusterIPRange      net.IPNet // 集群IP范围 次CIDR
	APIServerServiceIP                  net.IP    // ToDo api-server服务地址 与 AdvertiseAddress 有什么关系
	ServiceNodePortRange                utilnet.PortRange
	ProxyClientCertFile                 string
	ProxyClientKeyFile                  string
	EnableAggregatorRouting             bool
	AggregatorRejectForwardingRedirects bool // 聚合器拒绝将重定向响应转发回客户端.
	MasterCount                         int
	EndpointReconcilerType              string
	ServiceAccountSigningKeyFile        string                        // 对sa用户进行jwt签名使用的 密钥文件
	ServiceAccountIssuer                serviceaccount.TokenGenerator // 根据 /etc/kubernetes/pki/sa.key 生成对应的jwt token
	ServiceAccountTokenMaxExpiration    time.Duration                 // token 过期时间
	ShowHiddenMetricsForVersion         string
}

// NewServerRunOptions creates a new ServerRunOptions object with default parameters
func NewServerRunOptions() *ServerRunOptions {
	s := ServerRunOptions{
		GenericServerRunOptions: genericoptions.NewServerRunOptions(),                                                                   // kube-api-server ✅
		Etcd:                    genericoptions.NewEtcdOptions(storagebackend.NewDefaultConfig(kubeoptions.DefaultEtcdPathPrefix, nil)), // kube-api-server ✅
		SecureServing:           kubeoptions.NewSecureServingOptions(),                                                                  // kube-api-server ✅
		Audit:                   genericoptions.NewAuditOptions(),                                                                       // kube-api-server ✅
		Features:                genericoptions.NewFeatureOptions(),                                                                     // kube-api-server ✅
		Admission:               kubeoptions.NewAdmissionOptions(),                                                                      // kube-api-server ✅
		Authentication:          kubeoptions.NewBuiltInAuthenticationOptions().WithAll(),                                                // kube-api-server ✅
		Authorization:           kubeoptions.NewBuiltInAuthorizationOptions(),                                                           // kube-api-server ✅
		CloudProvider:           kubeoptions.NewCloudProviderOptions(),                                                                  // kube-api-server ✅
		APIEnablement:           genericoptions.NewAPIEnablementOptions(),                                                               // kube-api-server ✅
		EgressSelector:          genericoptions.NewEgressSelectorOptions(),                                                              // kube-api-server ✅
		Metrics:                 metrics.NewOptions(),                                                                                   // kube-api-server ✅
		Logs:                    logs.NewOptions(),                                                                                      // kube-api-server ✅
		Traces:                  genericoptions.NewTracingOptions(),                                                                     // kube-api-server ✅

		EnableLogsHandler:      true,
		EventTTL:               1 * time.Hour,
		MasterCount:            1,
		EndpointReconcilerType: string(reconcilers.LeaseEndpointReconcilerType),
		KubeletConfig: kubeletclient.KubeletClientConfig{
			Port:         ports.KubeletPort,         // 10250
			ReadOnlyPort: ports.KubeletReadOnlyPort, //
			PreferredAddressTypes: []string{
				// --override-hostname
				string(api.NodeHostName),
				string(api.NodeInternalDNS),
				string(api.NodeInternalIP),
				string(api.NodeExternalDNS),
				string(api.NodeExternalIP),
			},
			HTTPTimeout: time.Duration(5) * time.Second,
		},
		ServiceNodePortRange:                kubeoptions.DefaultServiceNodePortRange,
		AggregatorRejectForwardingRedirects: true,
	}
	s.Etcd.DefaultStorageMediaType = "application/vnd.kubernetes.protobuf"

	return &s
}

// Flags returns flags for a specific APIServer by section name
func (s *ServerRunOptions) Flags() (fss cliflag.NamedFlagSets) {
	// Add the generic flags.
	s.GenericServerRunOptions.AddUniversalFlags(fss.FlagSet("generic")) // ✅api server
	s.Etcd.AddFlags(fss.FlagSet("etcd"))                                // ✅api server
	s.SecureServing.AddFlags(fss.FlagSet("secure serving"))             // ✅api server
	s.Audit.AddFlags(fss.FlagSet("auditing"))                           // ✅api server
	s.Features.AddFlags(fss.FlagSet("features"))                        // ✅api server
	s.Authentication.AddFlags(fss.FlagSet("authentication"))            // ✅api server
	s.Authorization.AddFlags(fss.FlagSet("authorization"))              // ✅api server
	s.CloudProvider.AddFlags(fss.FlagSet("cloud provider"))             // ✅api server
	s.APIEnablement.AddFlags(fss.FlagSet("API enablement"))             // ✅api server
	s.EgressSelector.AddFlags(fss.FlagSet("egress selector"))           // ✅api server
	s.Admission.AddFlags(fss.FlagSet("admission"))                      // ✅api server
	s.Metrics.AddFlags(fss.FlagSet("metrics"))                          // ✅api server
	logsapi.AddFlags(s.Logs, fss.FlagSet("logs"))                       // ✅api server
	s.Traces.AddFlags(fss.FlagSet("traces"))                            // ✅api server

	fs := fss.FlagSet("misc")
	fs.DurationVar(&s.EventTTL, "event-ttl", s.EventTTL, "保留事件的时间.")
	fs.BoolVar(&s.AllowPrivileged, "allow-privileged", s.AllowPrivileged, "如果为真,则允许特权容器.(default=false)")
	fs.BoolVar(&s.EnableLogsHandler, "enable-logs-handler", s.EnableLogsHandler, "如果是,为apiserver日志添加一个 /logs 处理程序.")
	fs.MarkDeprecated("enable-logs-handler", "这个标志将在v1.19中被移除")
	fs.Int64Var(&s.MaxConnectionBytesPerSec, "max-connection-bytes-per-sec", s.MaxConnectionBytesPerSec, "如果非零,将每个用户连接限制为这个字节/秒数.目前仅适用于长时间运行的请求.")
	fs.IntVar(&s.MasterCount, "apiserver-count", s.MasterCount, "集群中运行的apiservers的数量必须为正数.(在启用--end-reconciler-type=master-count时使用.)")
	fs.MarkDeprecated("apiserver-count", "apiserver-count is deprecated and will be removed in a future version.")
	fs.StringVar(&s.EndpointReconcilerType, "endpoint-reconciler-type", s.EndpointReconcilerType, "使用端点协调器("+strings.Join(reconcilers.AllTypes.Names(), ", ")+") master-count 已弃用,并将在未来的版本中删除.")
	// See #14282 for details on how to test/try this option out.
	// TODO: remove this comment once this option is tested in CI.
	fs.IntVar(&s.KubernetesServiceNodePort, "kubernetes-service-node-port", s.KubernetesServiceNodePort, "如果非零，Kubernetes主服务(apiserver创建/维护的主服务)将是NodePort类型，使用这个作为端口的值。如果为0，则Kubernetes主服务的类型为ClusterIP。")
	fs.StringVar(&s.ServiceClusterIPRanges, "service-cluster-ip-range", s.ServiceClusterIPRanges, "集群服务的IP范围.这不能与分配给节点或pod的任何IP范围重叠.最多允许2个双栈cidr")
	fs.Var(&s.ServiceNodePortRange, "service-node-port-range", "为具有NodePort可见性的服务保留的端口范围  30000 - 32767")

	// Kubelet related flags:
	fs.StringSliceVar(&s.KubeletConfig.PreferredAddressTypes, "kubelet-preferred-address-types", s.KubeletConfig.PreferredAddressTypes, "用于kubelet连接的首选node address type列表。")
	fs.UintVar(&s.KubeletConfig.Port, "kubelet-port", s.KubeletConfig.Port, "弃用: kubelet port.")
	fs.MarkDeprecated("kubelet-port", "kubelet-port 已弃用并将被删除。")
	fs.UintVar(&s.KubeletConfig.ReadOnlyPort, "kubelet-read-only-port", s.KubeletConfig.ReadOnlyPort, "弃用: kubelet 只读端口")
	fs.MarkDeprecated("kubelet-read-only-port", "kubelet-read-only-port 已弃用并将被删除。")
	fs.DurationVar(&s.KubeletConfig.HTTPTimeout, "kubelet-timeout", s.KubeletConfig.HTTPTimeout, "kubelet操作超时.")
	fs.StringVar(&s.KubeletConfig.TLSClientConfig.CertFile, "kubelet-client-certificate", s.KubeletConfig.TLSClientConfig.CertFile, "TLS的客户端证书文件的路径。")
	fs.StringVar(&s.KubeletConfig.TLSClientConfig.KeyFile, "kubelet-client-key", s.KubeletConfig.TLSClientConfig.KeyFile, "TLS的客户端密钥文件的路径。")
	fs.StringVar(&s.KubeletConfig.TLSClientConfig.CAFile, "kubelet-certificate-authority", s.KubeletConfig.TLSClientConfig.CAFile, "证书颁发机构的证书文件的路径。")
	fs.StringVar(&s.ProxyClientCertFile, "proxy-client-cert-file", s.ProxyClientCertFile, "客户端证书，用于在请求期间必须调用聚合器或kube-apiserver时证明它的身份。这包括代理请求到用户api服务器和调用webhook许可插件。")
	fs.StringVar(&s.ProxyClientKeyFile, "proxy-client-key-file", s.ProxyClientKeyFile, "客户端证书的私钥，用于在请求期间必须调用聚合器或kube-apiserver时证明聚合器的身份。这包括代理请求到用户api服务器和调用webhook许可插件。")
	fs.BoolVar(&s.EnableAggregatorRouting, "enable-aggregator-routing", s.EnableAggregatorRouting, "打开聚合器将请求路由到端点IP而不是集群IP。")
	fs.BoolVar(&s.AggregatorRejectForwardingRedirects, "aggregator-reject-forwarding-redirect", s.AggregatorRejectForwardingRedirects, "聚合器拒绝将重定向响应转发回客户端.")
	fs.StringVar(&s.ServiceAccountSigningKeyFile, "service-account-signing-key-file", s.ServiceAccountSigningKeyFile, "对sa用户进行jwt签名使用的 密钥文件.")

	return fss
}
