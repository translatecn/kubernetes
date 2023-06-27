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

package v1beta1

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logsapi "k8s.io/component-base/logs/api/v1"
	tracingapi "k8s.io/component-base/tracing/api/v1"
)

// HairpinMode denotes how the kubelet should configure networking to handle
// hairpin packets.
type HairpinMode string

// Enum settings for different ways to handle hairpin packets.
const (
	// Set the hairpin flag on the veth of containers in the respective
	// container runtime.
	HairpinVeth = "hairpin-veth"
	// Make the container bridge promiscuous. This will force it to accept
	// hairpin packets, even if the flag isn't set on ports of the bridge.
	PromiscuousBridge = "promiscuous-bridge"
	// Neither of the above. If the kubelet is started in this hairpin mode
	// and kube-proxy is running in iptables mode, hairpin packets will be
	// dropped by the container bridge.
	HairpinNone = "none"
)

// ResourceChangeDetectionStrategy denotes a mode in which internal
// managers (secret, configmap) are discovering object changes.
type ResourceChangeDetectionStrategy string

// 用于设置 kubelet 管理器的不同策略
const (
	GetChangeDetectionStrategy          ResourceChangeDetectionStrategy = "Get"              // kubelet 从 apiserver 直接获取必要的对象.
	TTLCacheChangeDetectionStrategy     ResourceChangeDetectionStrategy = "Cache"            // kubelet 使用 ttl 缓存来获取从 apiserver 直接获取的对象.
	WatchChangeDetectionStrategy        ResourceChangeDetectionStrategy = "Watch"            // kubelet 使用 watch 来观察感兴趣的对象的变化.
	RestrictedTopologyManagerPolicy                                     = "restricted"       // 分配的资源无法正确对齐,它将导致 pod 准入失败
	BestEffortTopologyManagerPolicy                                     = "best-effort"      // 尝试尽可能地对齐 NUMA 节点上的分配
	NoneTopologyManagerPolicy                                           = "none"             // 不会尝试进行任何资源调整
	SingleNumaNodeTopologyManagerPolicy                                 = "single-numa-node" // 只有当所有请求的 CPU 和设备都可以从一个 NUMA 节点分配时,pod 准入才会通过.
	ContainerTopologyManagerScope                                       = "container"        // 拓扑策略适用于每个容器
	PodTopologyManagerScope                                             = "pod"              // 拓扑策略适用于每个 Pod.
	NoneMemoryManagerPolicy                                             = "None"             //
	StaticMemoryManagerPolicy                                           = "Static"           // 尝试将保证pod的容器内存固定到NUMA节点的最小子集
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// KubeletConfiguration contains the configuration for the Kubelet
type KubeletConfiguration struct {
	metav1.TypeMeta `json:",inline"`

	// enableServer enables Kubelet's secured server.2
	// Note: Kubelet's insecure port is controlled by the readOnlyPort option.
	// Default: true
	EnableServer       *bool               `json:"enableServer,omitempty"`
	StaticPodPath      string              `json:"staticPodPath,omitempty"`      // 静态pod的文件夹 Default: ""
	SyncFrequency      metav1.Duration     `json:"syncFrequency,omitempty"`      // 周期性全量同步容器、配置的间隔 Default: "1m"
	FileCheckFrequency metav1.Duration     `json:"fileCheckFrequency,omitempty"` // 静态pod文件检查周期 Default: "20s"
	HTTPCheckFrequency metav1.Duration     `json:"httpCheckFrequency,omitempty"` // 静态pod http 检查周期 Default: "20s"
	StaticPodURL       string              `json:"staticPodURL,omitempty"`       // 获取静态文件列表的地址 Default: ""
	StaticPodURLHeader map[string][]string `json:"staticPodURLHeader,omitempty"` // 获取静态文件列表的地址,需要使用一些 HTTP 头部信息 Default: nil
	// address is the IP address for the Kubelet to serve on (set to 0.0.0.0
	// for all interfaces).
	// Default: "0.0.0.0"
	// +optional
	Address string `json:"address,omitempty"`
	// port is the port for the Kubelet to serve on.
	// The port number must be between 1 and 65535, inclusive.
	// Default: 10250
	// +optional
	Port         int32 `json:"port,omitempty"`
	ReadOnlyPort int32 `json:"readOnlyPort,omitempty"` // 0 禁用
	// tlsCertFile is the file containing x509 Certificate for HTTPS. (CA cert,
	// if any, concatenated after server cert). If tlsCertFile and
	// tlsPrivateKeyFile are not provided, a self-signed certificate
	// and key are generated for the public address and saved to the directory
	// passed to the Kubelet's --cert-dir flag.
	// Default: ""
	// +optional
	TLSCertFile string `json:"tlsCertFile,omitempty"`
	// tlsPrivateKeyFile is the file containing x509 private key matching tlsCertFile.
	// Default: ""
	// +optional
	TLSPrivateKeyFile string `json:"tlsPrivateKeyFile,omitempty"`
	// tlsCipherSuites is the list of allowed cipher suites for the server.
	// Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants).
	// Default: nil
	// +optional
	TLSCipherSuites []string `json:"tlsCipherSuites,omitempty"`
	// tlsMinVersion is the minimum TLS version supported.
	// Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants).
	// Default: ""
	// +optional
	TLSMinVersion string `json:"tlsMinVersion,omitempty"`
	// rotateCertificates enables client certificate rotation. The Kubelet will request a
	// new certificate from the certificates.k8s.io API. This requires an approver to approve the
	// certificate signing requests.
	// Default: false
	// +optional
	RotateCertificates bool `json:"rotateCertificates,omitempty"`
	// serverTLSBootstrap enables server certificate bootstrap. Instead of self
	// signing a serving certificate, the Kubelet will request a certificate from
	// the 'certificates.k8s.io' API. This requires an approver to approve the
	// certificate signing requests (CSR). The RotateKubeletServerCertificate feature
	// must be enabled when setting this field.
	// Default: false
	// +optional
	ServerTLSBootstrap bool `json:"serverTLSBootstrap,omitempty"`
	// authentication specifies how requests to the Kubelet's server are authenticated.
	// Defaults:
	//   anonymous:
	//     enabled: false
	//   webhook:
	//     enabled: true
	//     cacheTTL: "2m"
	// +optional
	Authentication KubeletAuthentication `json:"authentication"`
	// authorization specifies how requests to the Kubelet's server are authorized.
	// Defaults:
	//   mode: Webhook
	//   webhook:
	//     cacheAuthorizedTTL: "5m"
	//     cacheUnauthorizedTTL: "30s"
	// +optional
	Authorization KubeletAuthorization `json:"authorization"`
	// registryPullQPS is the limit of registry pulls per second.
	// The value must not be a negative number.
	// Setting it to 0 means no limit.
	// Default: 5
	// +optional
	RegistryPullQPS *int32 `json:"registryPullQPS,omitempty"`
	// registryBurst is the maximum size of bursty pulls, temporarily allows
	// pulls to burst to this number, while still not exceeding registryPullQPS.
	// The value must not be a negative number.
	// Only used if registryPullQPS is greater than 0.
	// Default: 10
	// +optional
	RegistryBurst int32 `json:"registryBurst,omitempty"`
	// eventRecordQPS is the maximum event creations per second. If 0, there
	// is no limit enforced. The value cannot be a negative number.
	// Default: 5
	// +optional
	EventRecordQPS *int32 `json:"eventRecordQPS,omitempty"`
	// eventBurst is the maximum size of a burst of event creations, temporarily
	// allows event creations to burst to this number, while still not exceeding
	// eventRecordQPS. This field canot be a negative number and it is only used
	// when eventRecordQPS > 0.
	// Default: 10
	// +optional
	EventBurst int32 `json:"eventBurst,omitempty"`
	// enableDebuggingHandlers enables server endpoints for log access
	// and local running of containers and commands, including the exec,
	// attach, logs, and portforward features.
	// Default: true
	// +optional
	EnableDebuggingHandlers *bool `json:"enableDebuggingHandlers,omitempty"`
	// enableContentionProfiling enables lock contention profiling, if enableDebuggingHandlers is true.
	// Default: false
	// +optional
	EnableContentionProfiling bool `json:"enableContentionProfiling,omitempty"`
	// healthzPort is the port of the localhost healthz endpoint (set to 0 to disable).
	// A valid number is between 1 and 65535.
	// Default: 10248
	// +optional
	HealthzPort *int32 `json:"healthzPort,omitempty"`
	// healthzBindAddress is the IP address for the healthz server to serve on.
	// Default: "127.0.0.1"
	// +optional
	HealthzBindAddress string `json:"healthzBindAddress,omitempty"`
	// oomScoreAdj is The oom-score-adj value for kubelet process. Values
	// must be within the range [-1000, 1000].
	// Default: -999
	// +optional
	OOMScoreAdj *int32 `json:"oomScoreAdj,omitempty"`
	// clusterDomain is the DNS domain for this cluster. If set, kubelet will
	// configure all containers to search this domain in addition to the
	// host's search domains.
	// Default: ""
	// +optional
	ClusterDomain string   `json:"clusterDomain,omitempty"`
	ClusterDNS    []string `json:"clusterDNS,omitempty"` // 逗号分隔的 DNS 服务器 IP 地址列表,kubelet 会使用	// Default: nil
	// streamingConnectionIdleTimeout is the maximum time a streaming connection
	// can be idle before the connection is automatically closed.
	// Default: "4h"
	// +optional
	StreamingConnectionIdleTimeout metav1.Duration `json:"streamingConnectionIdleTimeout,omitempty"`
	// nodeStatusUpdateFrequency is the frequency that kubelet computes node
	// status. If node lease feature is not enabled, it is also the frequency that
	// kubelet posts node status to master.
	// Note: When node lease feature is not enabled, be cautious when changing the
	// constant, it must work with nodeMonitorGracePeriod in nodecontroller.
	// Default: "10s"
	// +optional
	NodeStatusUpdateFrequency metav1.Duration `json:"nodeStatusUpdateFrequency,omitempty"`
	// nodeStatusReportFrequency is the frequency that kubelet posts node
	// status to master if node status does not change. Kubelet will ignore this
	// frequency and post node status immediately if any change is detected. It is
	// only used when node lease feature is enabled. nodeStatusReportFrequency's
	// default value is 5m. But if nodeStatusUpdateFrequency is set explicitly,
	// nodeStatusReportFrequency's default value will be set to
	// nodeStatusUpdateFrequency for backward compatibility.
	// Default: "5m"
	// +optional
	NodeStatusReportFrequency metav1.Duration `json:"nodeStatusReportFrequency,omitempty"`
	NodeLeaseDurationSeconds  int32           `json:"nodeLeaseDurationSeconds,omitempty"` // nodeLeaseDurationSeconds  Kubelet将在其相应的Lease上设置的持续时间. 	// Default: 40
	// imageMinimumGCAge is the minimum age for an unused image before it is
	// garbage collected.
	// Default: "2m"
	// +optional
	ImageMinimumGCAge           metav1.Duration `json:"imageMinimumGCAge,omitempty"`
	ImageGCHighThresholdPercent *int32          `json:"imageGCHighThresholdPercent,omitempty"` // 运行image GC的磁盘使用百分比.取值范围为[0,100],不启用image gcc回收,defau.
	ImageGCLowThresholdPercent  *int32          `json:"imageGCLowThresholdPercent,omitempty"`  // 在此之前从未运行image GC的磁盘使用百分比.要进行垃圾收集的磁盘使用率最低.取值必须在[0,100]范围内,且不能大于--image-gc-high-threshold   default 80
	VolumeStatsAggPeriod        metav1.Duration `json:"volumeStatsAggPeriod,omitempty"`        // 计算和缓存所有pod卷磁盘使用量的频率  default 1m
	// kubeletCgroups is the absolute name of cgroups to isolate the kubelet in
	// Default: ""
	// +optional
	KubeletCgroups string `json:"kubeletCgroups,omitempty"`
	// systemCgroups is absolute name of cgroups in which to place
	// all non-kernel processes that are not already in a container. Empty
	// for no container. Rolling back the flag requires a reboot.
	// The cgroupRoot must be specified if this field is not empty.
	// Default: ""
	// +optional
	SystemCgroups string `json:"systemCgroups,omitempty"`
	CgroupRoot    string `json:"cgroupRoot,omitempty"`    // CgroupRoot是用于pod的根cgroup如果启用了CgroupsPerQOS,则这是QoS cgroup层次结构的根.
	CgroupsPerQOS *bool  `json:"cgroupsPerQOS,omitempty"` // 启用基于QoS的Cgroup层次结构:QoS类的顶级Cgroup,所有Burstable和bestefort pod都在其特定的顶级QoS Cgroup下.   默认true
	CgroupDriver  string `json:"cgroupDriver,omitempty"`  // kubelet用来在主机上操作cgroups的驱动程序(cgroupfs或systemd)Default: "cgroupfs"
	// cpuManagerPolicy is the name of the policy to use.
	// Requires the CPUManager feature gate to be enabled.
	// Default: "None"
	// +optional
	CPUManagerPolicy string `json:"cpuManagerPolicy,omitempty"`
	// cpuManagerPolicyOptions is a set of key=value which 	allows to set extra options
	// to fine tune the behaviour of the cpu manager policies.
	// Requires  both the "CPUManager" and "CPUManagerPolicyOptions" feature gates to be enabled.
	// Default: nil
	// +optional
	CPUManagerPolicyOptions map[string]string `json:"cpuManagerPolicyOptions,omitempty"`
	// cpuManagerReconcilePeriod is the reconciliation period for the CPU Manager.
	// Requires the CPUManager feature gate to be enabled.
	// Default: "10s"
	// +optional
	CPUManagerReconcilePeriod metav1.Duration `json:"cpuManagerReconcilePeriod,omitempty"`
	// memoryManagerPolicy is the name of the policy to use by memory manager.
	// Requires the MemoryManager feature gate to be enabled.
	// Default: "none"
	// +optional
	MemoryManagerPolicy string `json:"memoryManagerPolicy,omitempty"`
	// topologyManagerPolicy is the name of the topology manager policy to use.
	// Valid values include:
	//
	// - `restricted`: kubelet only allows pods with optimal NUMA node alignment for
	//   requested resources;
	// - `best-effort`: kubelet will favor pods with NUMA alignment of CPU and device
	//   resources;
	// - `none`: kubelet has no knowledge of NUMA alignment of a pod's CPU and device resources.
	// - `single-numa-node`: kubelet only allows pods with a single NUMA alignment
	//   of CPU and device resources.
	//
	// Policies other than "none" require the TopologyManager feature gate to be enabled.
	// Default: "none"
	// +optional
	TopologyManagerPolicy string `json:"topologyManagerPolicy,omitempty"` // 策略名称,除了 "none" 之外的策略需要启用 TopologyManager 功能门控.一般都开启
	// topologyManagerScope represents the scope of topology hint generation
	// that topology manager requests and hint providers generate. Valid values include:
	//
	// - `container`: topology policy is applied on a per-container basis.
	// - `pod`: topology policy is applied on a per-pod basis.
	//
	// "pod" scope requires the TopologyManager feature gate to be enabled.
	// Default: "container"
	// +optional
	TopologyManagerScope         string            `json:"topologyManagerScope,omitempty"`         // 拓扑管理器请求和提示提供程序生成的拓扑提示的范围. Default: "container"
	TopologyManagerPolicyOptions map[string]string `json:"topologyManagerPolicyOptions,omitempty"` // 一组key=value,它允许设置额外的选项来微调拓扑管理器策略的行为.	// Default: nil
	// qosReserved is a set of resource name to percentage pairs that specify
	// the minimum percentage of a resource reserved for exclusive use by the
	// guaranteed QoS tier.
	// Currently supported resources: "memory"
	// Requires the QOSReserved feature gate to be enabled.
	// Default: nil
	// +optional
	QOSReserved map[string]string `json:"qosReserved,omitempty"`
	// runtimeRequestTimeout is the timeout for all runtime requests except long running
	// requests - pull, logs, exec and attach.
	// Default: "2m"
	// +optional
	RuntimeRequestTimeout metav1.Duration `json:"runtimeRequestTimeout,omitempty"`
	// hairpinMode specifies how the Kubelet should configure the container
	// bridge for hairpin packets.
	// Setting this flag allows endpoints in a Service to loadbalance back to
	// themselves if they should try to access their own Service. Values:
	//
	// - "promiscuous-bridge": make the container bridge promiscuous.
	// - "hairpin-veth":       set the hairpin flag on container veth interfaces.
	// - "none":               do nothing.
	//
	// Generally, one must set `--hairpin-mode=hairpin-veth to` achieve hairpin NAT,
	// because promiscuous-bridge assumes the existence of a container bridge named cbr0.
	// Default: "promiscuous-bridge"
	// +optional
	HairpinMode string `json:"hairpinMode,omitempty"`
	MaxPods     int32  `json:"maxPods,omitempty"` // maxPods is the maximum 可以在Kubelet上运行的pod的数量. Default: 110
	// podCIDR is the CIDR to use for pod IP addresses, only used in standalone mode.
	// In cluster mode, this is obtained from the control plane.
	// Default: ""
	// +optional
	PodCIDR      string `json:"podCIDR,omitempty"`
	PodPidsLimit *int64 `json:"podPidsLimit,omitempty"` // pod中pid的最大数目.Default: -1
	// resolvConf is the resolver configuration file used as the basis
	// for the container DNS resolution configuration.
	// If set to the empty string, will override the default and effectively disable DNS lookups.
	// Default: "/etc/resolv.conf"
	// +optional
	ResolverConfig *string `json:"resolvConf,omitempty"`
	RunOnce        bool    `json:"runOnce,omitempty"` // Kubelet 仅检查一次 API 服务器以获取 Pod,运行这些 Pod 并在完成后退出,除了静态 Pod 文件中指定的 Pod 之外Default: false
	// cpuCFSQuota enables CPU CFS quota enforcement for containers that
	// specify CPU limits.
	// Default: true
	// +optional
	CPUCFSQuota *bool `json:"cpuCFSQuota,omitempty"`
	// cpuCFSQuotaPeriod is the CPU CFS quota period value, `cpu.cfs_period_us`.
	// The value must be between 1 ms and 1 second, inclusive.
	// Requires the CustomCPUCFSQuotaPeriod feature gate to be enabled.
	// Default: "100ms"
	// +optional
	CPUCFSQuotaPeriod *metav1.Duration `json:"cpuCFSQuotaPeriod,omitempty"`
	// nodeStatusMaxImages caps the number of images reported in Node.status.images.
	// The value must be greater than -2.
	// Note: If -1 is specified, no cap will be applied. If 0 is specified, no image is returned.
	// Default: 50
	// +optional
	NodeStatusMaxImages *int32 `json:"nodeStatusMaxImages,omitempty"`
	// maxOpenFiles is Number of files that can be opened by Kubelet process.
	// The value must be a non-negative number.
	// Default: 1000000
	// +optional
	MaxOpenFiles int64 `json:"maxOpenFiles,omitempty"`
	// contentType is contentType of requests sent to apiserver.
	// Default: "application/vnd.kubernetes.protobuf"
	// +optional
	ContentType string `json:"contentType,omitempty"`
	// kubeAPIQPS is the QPS to use while talking with kubernetes apiserver.
	// Default: 5
	// +optional
	KubeAPIQPS *int32 `json:"kubeAPIQPS,omitempty"`
	// kubeAPIBurst is the burst to allow while talking with kubernetes API server.
	// This field cannot be a negative number.
	// Default: 10
	// +optional
	KubeAPIBurst int32 `json:"kubeAPIBurst,omitempty"`
	// serializeImagePulls when enabled, tells the Kubelet to pull images one
	// at a time. We recommend *not* changing the default value on nodes that
	// run docker daemon with version  < 1.9 or an Aufs storage backend.
	// Issue #10959 has more details.
	// Default: true
	// +optional
	SerializeImagePulls *bool `json:"serializeImagePulls,omitempty"`
	// evictionHard is a map of signal names to quantities that defines hard eviction
	// thresholds. For example: `{"memory.available": "300Mi"}`.
	// To explicitly disable, pass a 0% or 100% threshold on an arbitrary resource.
	// Default:
	//   memory.available:  "100Mi"
	//   nodefs.available:  "10%"
	//   nodefs.inodesFree: "5%"
	//   imagefs.available: "15%"
	// +optional
	EvictionHard map[string]string `json:"evictionHard,omitempty"`
	// evictionSoft is a map of signal names to quantities that defines soft eviction thresholds.
	// For example: `{"memory.available": "300Mi"}`.
	// Default: nil
	// +optional
	EvictionSoft map[string]string `json:"evictionSoft,omitempty"`
	// evictionSoftGracePeriod is a map of signal names to quantities that defines grace
	// periods for each soft eviction signal. For example: `{"memory.available": "30s"}`.
	// Default: nil
	// +optional
	EvictionSoftGracePeriod map[string]string `json:"evictionSoftGracePeriod,omitempty"`
	// evictionPressureTransitionPeriod is the duration for which the kubelet has to wait
	// before transitioning out of an eviction pressure condition.
	// Default: "5m"
	// +optional
	EvictionPressureTransitionPeriod metav1.Duration `json:"evictionPressureTransitionPeriod,omitempty"`
	// evictionMaxPodGracePeriod is the maximum allowed grace period (in seconds) to use
	// when terminating pods in response to a soft eviction threshold being met. This value
	// effectively caps the Pod's terminationGracePeriodSeconds value during soft evictions.
	// Note: Due to issue #64530, the behavior has a bug where this value currently just
	// overrides the grace period during soft eviction, which can increase the grace
	// period from what is set on the Pod. This bug will be fixed in a future release.
	// Default: 0
	// +optional
	EvictionMaxPodGracePeriod int32 `json:"evictionMaxPodGracePeriod,omitempty"`
	// evictionMinimumReclaim is a map of signal names to quantities that defines minimum reclaims,
	// which describe the minimum amount of a given resource the kubelet will reclaim when
	// performing a pod eviction while that resource is under pressure.
	// For example: `{"imagefs.available": "2Gi"}`.
	// Default: nil
	// +optional
	EvictionMinimumReclaim map[string]string `json:"evictionMinimumReclaim,omitempty"`
	// podsPerCore is the maximum number of pods per core. Cannot exceed maxPods.
	// The value must be a non-negative integer.
	// If 0, there is no limit on the number of Pods.
	// Default: 0
	// +optional
	PodsPerCore int32 `json:"podsPerCore,omitempty"`
	// enableControllerAttachDetach enables the Attach/Detach controller to
	// manage attachment/detachment of volumes scheduled to this node, and
	// disables kubelet from executing any attach/detach operations.
	// Note: attaching/detaching CSI volumes is not supported by the kubelet,
	// so this option needs to be true for that use case.
	// Default: true
	// +optional
	EnableControllerAttachDetach *bool `json:"enableControllerAttachDetach,omitempty"`
	ProtectKernelDefaults        bool  `json:"protectKernelDefaults,omitempty"`  // 如果 protectKernelDefaults 为 true,则会导致 Kubelet 在内核标志不符合其预期时出错.否则,Kubelet 将尝试修改内核标志以匹配其预期.	// Default: false
	MakeIPTablesUtilChains       *bool `json:"makeIPTablesUtilChains,omitempty"` // 如果为true, kubelet将确保主机上存在iptables实用程序规则.这些规则将作为各种组件的实用工具,例如kube-proxy.规则将基于IPTablesMasqueradeBit和IPTablesDropBit创建.// Default: true
	// iptablesMasqueradeBit is the bit of the iptables fwmark space to mark for SNAT.
	// Values must be within the range [0, 31]. Must be different from other mark bits.
	// Warning: Please match the value of the corresponding parameter in kube-proxy.
	// TODO: clean up IPTablesMasqueradeBit in kube-proxy.
	// Default: 14
	// +optional
	IPTablesMasqueradeBit *int32 `json:"iptablesMasqueradeBit,omitempty"`
	// iptablesDropBit is the bit of the iptables fwmark space to mark for dropping packets.
	// Values must be within the range [0, 31]. Must be different from other mark bits.
	// Default: 15
	// +optional
	IPTablesDropBit *int32 `json:"iptablesDropBit,omitempty"`
	// featureGates is a map of feature names to bools that enable or disable experimental
	// features. This field modifies piecemeal the built-in default values from
	// "k8s.io/kubernetes/pkg/features/kube_features.go".
	// Default: nil
	// +optional
	FeatureGates map[string]bool `json:"featureGates,omitempty"`
	FailSwapOn   *bool           `json:"failSwapOn,omitempty"` // 告诉Kubelet,如果在节点上启用了swap,则启动失败.默认为true
	// memorySwap configures swap memory available to container workloads.
	// +featureGate=NodeSwap
	// +optional
	MemorySwap MemorySwapConfiguration `json:"memorySwap,omitempty"`
	// containerLogMaxSize is a quantity defining the maximum size of the container log
	// file before it is rotated. For example: "5Mi" or "256Ki".
	// Default: "10Mi"
	// +optional
	ContainerLogMaxSize string `json:"containerLogMaxSize,omitempty"`
	// containerLogMaxFiles specifies the maximum number of container log files that can
	// be present for a container.
	// Default: 5
	// +optional
	ContainerLogMaxFiles *int32 `json:"containerLogMaxFiles,omitempty"`
	// configMapAndSecretChangeDetectionStrategy is a mode in which ConfigMap and Secret
	// managers are running. Valid values include:
	//
	// - `Get`: kubelet fetches necessary objects directly from the API server;
	// - `Cache`: kubelet uses TTL cache for object fetched from the API server;
	// - `Watch`: kubelet uses watches to observe changes to objects that are in its interest.
	//
	// Default: "Watch"
	// +optional
	ConfigMapAndSecretChangeDetectionStrategy ResourceChangeDetectionStrategy `json:"configMapAndSecretChangeDetectionStrategy,omitempty"`
	SystemReserved                            map[string]string               `json:"systemReserved,omitempty"` // 预留资源,只支持  cpu=200m,memory=150G,ephemeral-storage=1G,pid=100 Default: nil
	KubeReserved                              map[string]string               `json:"kubeReserved,omitempty"`   // 预留资源,只支持  cpu=200m,memory=150G,ephemeral-storage=1G,pid=100 Default: nil
	// The reservedSystemCPUs option specifies the CPU list reserved for the host
	// level system threads and kubernetes related threads. This provide a "static"
	// CPU list rather than the "dynamic" list by systemReserved and kubeReserved.
	// This option does not support systemReservedCgroup or kubeReservedCgroup.
	ReservedSystemCPUs string `json:"reservedSystemCPUs,omitempty"`
	// showHiddenMetricsForVersion is the previous version for which you want to show
	// hidden metrics.
	// Only the previous minor version is meaningful, other values will not be allowed.
	// The format is `<major>.<minor>`, e.g.: `1.16`.
	// The purpose of this format is make sure you have the opportunity to notice
	// if the next release hides additional metrics, rather than being surprised
	// when they are permanently removed in the release after that.
	// Default: ""
	// +optional
	ShowHiddenMetricsForVersion string `json:"showHiddenMetricsForVersion,omitempty"`
	// systemReservedCgroup helps the kubelet identify absolute name of top level CGroup used
	// to enforce `systemReserved` compute resource reservation for OS system daemons.
	// Refer to [Node Allocatable](https://git.k8s.io/community/contributors/design-proposals/node/node-allocatable.md)
	// doc for more information.
	// Default: ""
	// +optional
	SystemReservedCgroup string `json:"systemReservedCgroup,omitempty"`
	// kubeReservedCgroup helps the kubelet identify absolute name of top level CGroup used
	// to enforce `KubeReserved` compute resource reservation for Kubernetes node system daemons.
	// Refer to [Node Allocatable](https://git.k8s.io/community/contributors/design-proposals/node/node-allocatable.md)
	// doc for more information.
	// Default: ""
	// +optional
	KubeReservedCgroup string `json:"kubeReservedCgroup,omitempty"`
	// This flag specifies the various Node Allocatable enforcements that Kubelet needs to perform.
	// This flag accepts a list of options. Acceptable options are `none`, `pods`,
	// `system-reserved` and `kube-reserved`.
	// If `none` is specified, no other options may be specified.
	// When `system-reserved` is in the list, systemReservedCgroup must be specified.
	// When `kube-reserved` is in the list, kubeReservedCgroup must be specified.
	// This field is supported only when `cgroupsPerQOS` is set to true.
	// Refer to [Node Allocatable](https://git.k8s.io/community/contributors/design-proposals/node/node-allocatable.md)
	// for more information.
	// Default: ["pods"]
	// +optional
	EnforceNodeAllocatable []string `json:"enforceNodeAllocatable,omitempty"`
	AllowedUnsafeSysctls   []string `json:"allowedUnsafeSysctls,omitempty"` // 被允许的 sysctl 不安全指令;这些系统设置了名称空间,但默认情况下不允许. `kernel.shm*`, `kernel.msg*`, `kernel.sem`, `fs.mqueue.*`, and `net.*`.Default: []

	VolumePluginDir string `json:"volumePluginDir,omitempty"` // 搜索其他第三方卷插件的完整目录路径.该目录下可能包含用于kubernetes的自定义卷插件,这些插件可以通过该目录进行加载和使用.	// Default: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"

	// providerID, if set, sets the unique ID of the instance that an external
	// provider (i.e. cloudprovider) can use to identify a specific node.
	// Default: ""
	// +optional
	ProviderID              string `json:"providerID,omitempty"`
	KernelMemcgNotification bool   `json:"kernelMemcgNotification,omitempty"` // 如果为true,将与内核memcg通知集成,以确定是否超过内存阈值.Default: false
	// logging specifies the options of logging.
	// Refer to [Logs Options](https://github.com/kubernetes/component-base/blob/master/logs/options.go)
	// for more information.
	// Default:
	//   Format: text
	// + optional
	Logging logsapi.LoggingConfiguration `json:"logging,omitempty"`
	// enableSystemLogHandler enables system logs via web interface host:port/logs/
	// Default: true
	// +optional
	EnableSystemLogHandler *bool `json:"enableSystemLogHandler,omitempty"`
	// +featureGate=GracefulNodeShutdown
	// +optional
	ShutdownGracePeriod metav1.Duration `json:"shutdownGracePeriod,omitempty"` // 节点关闭时，容器优雅关闭等待的时间Default: "0s"
	// +featureGate=GracefulNodeShutdown
	// +optional
	ShutdownGracePeriodCriticalPods metav1.Duration `json:"shutdownGracePeriodCriticalPods,omitempty"` // 指定分配给节点优雅关闭等待的时间,默认0s.if ShutdownGracePeriod=30s, and ShutdownGracePeriodCriticalPods=10s, 在 node 关闭期间,前20秒将保留用于优雅地终止正常pod,最后10秒将保留用于终止关键pod.
	// shutdownGracePeriodByPodPriority specifies the shutdown grace period for Pods based
	// on their associated priority class value.
	// When a shutdown request is received, the Kubelet will initiate shutdown on all pods
	// running on the node with a grace period that depends on the priority of the pod,
	// and then wait for all pods to exit.
	// Each entry in the array represents the graceful shutdown time a pod with a priority
	// class value that lies in the range of that value and the next higher entry in the
	// list when the node is shutting down.
	// For example, to allow critical pods 10s to shutdown, priority>=10000 pods 20s to
	// shutdown, and all remaining pods 30s to shutdown.
	//
	// shutdownGracePeriodByPodPriority:
	//   - priority: 2000000000
	//     shutdownGracePeriodSeconds: 10
	//   - priority: 10000
	//     shutdownGracePeriodSeconds: 20
	//   - priority: 0
	//     shutdownGracePeriodSeconds: 30
	//
	// The time the Kubelet will wait before exiting will at most be the maximum of all
	// shutdownGracePeriodSeconds for each priority class range represented on the node.
	// When all pods have exited or reached their grace periods, the Kubelet will release
	// the shutdown inhibit lock.
	// Requires the GracefulNodeShutdown feature gate to be enabled.
	// This configuration must be empty if either ShutdownGracePeriod or ShutdownGracePeriodCriticalPods is set.
	// Default: nil
	// +featureGate=GracefulNodeShutdownBasedOnPodPriority
	// +optional
	ShutdownGracePeriodByPodPriority []ShutdownGracePeriodByPodPriority `json:"shutdownGracePeriodByPodPriority,omitempty"`
	// reservedMemory specifies a comma-separated list of memory reservations for NUMA nodes.
	// The parameter makes sense only in the context of the memory manager feature.
	// The memory manager will not allocate reserved memory for container workloads.
	// For example, if you have a NUMA0 with 10Gi of memory and the reservedMemory was
	// specified to reserve 1Gi of memory at NUMA0, the memory manager will assume that
	// only 9Gi is available for allocation.
	// You can specify a different amount of NUMA node and memory types.
	// You can omit this parameter at all, but you should be aware that the amount of
	// reserved memory from all NUMA nodes should be equal to the amount of memory specified
	// by the [node allocatable](https://kubernetes.io/docs/tasks/administer-cluster/reserve-compute-resources/#node-allocatable).
	// If at least one node allocatable parameter has a non-zero value, you will need
	// to specify at least one NUMA node.
	// Also, avoid specifying:
	//
	// 1. Duplicates, the same NUMA node, and memory type, but with a different value.
	// 2. zero limits for any memory type.
	// 3. NUMAs nodes IDs that do not exist under the machine.
	// 4. memory types except for memory and hugepages-<size>
	//
	// Default: nil
	// +optional
	ReservedMemory []MemoryReservation `json:"reservedMemory,omitempty"`
	// enableProfilingHandler enables profiling via web interface host:port/debug/pprof/
	// Default: true
	// +optional
	EnableProfilingHandler *bool `json:"enableProfilingHandler,omitempty"`
	// enableDebugFlagsHandler enables flags endpoint via web interface host:port/debug/flags/v
	// Default: true
	// +optional
	EnableDebugFlagsHandler *bool `json:"enableDebugFlagsHandler,omitempty"`
	// SeccompDefault enables the use of `RuntimeDefault` as the default seccomp profile for all workloads.
	// This requires the corresponding SeccompDefault feature gate to be enabled as well.
	// Default: false
	// +optional
	SeccompDefault *bool `json:"seccompDefault,omitempty"`
	// MemoryThrottlingFactor specifies the factor multiplied by the memory limit or node allocatable memory
	// when setting the cgroupv2 memory.high value to enforce MemoryQoS.
	// Decreasing this factor will set lower high limit for container cgroups and put heavier reclaim pressure
	// while increasing will put less reclaim pressure.
	// See https://kep.k8s.io/2570 for more details.
	// Default: 0.8
	// +featureGate=MemoryQoS
	// +optional
	MemoryThrottlingFactor *float64 `json:"memoryThrottlingFactor,omitempty"`
	// registerWithTaints are an array of taints to add to a node object when
	// the kubelet registers itself. This only takes effect when registerNode
	// is true and upon the initial registration of the node.
	// Default: nil
	// +optional
	RegisterWithTaints []v1.Taint `json:"registerWithTaints,omitempty"`
	// registerNode enables automatic registration with the apiserver.
	// Default: true
	// +optional
	RegisterNode *bool `json:"registerNode,omitempty"`
	// Tracing specifies the versioned configuration for OpenTelemetry tracing clients.
	// See https://kep.k8s.io/2832 for more details.
	// +featureGate=KubeletTracing
	// +optional
	Tracing *tracingapi.TracingConfiguration `json:"tracing,omitempty"`

	// LocalStorageCapacityIsolation enables local ephemeral storage isolation feature. The default setting is true.
	// This feature allows users to set request/limit for container's ephemeral storage and manage it in a similar way
	// as cpu and memory. It also allows setting sizeLimit for emptyDir volume, which will trigger pod eviction if disk
	// usage from the volume exceeds the limit.
	// This feature depends on the capability of detecting correct root file system disk usage. For certain systems,
	// such as kind rootless, if this capability cannot be supported, the feature LocalStorageCapacityIsolation should be
	// disabled. Once disabled, user should not set request/limit for container's ephemeral storage, or sizeLimit for emptyDir.
	// Default: true
	// +optional
	LocalStorageCapacityIsolation *bool `json:"localStorageCapacityIsolation,omitempty"`
}

type KubeletAuthorizationMode string

const (
	// KubeletAuthorizationModeAlwaysAllow authorizes all authenticated requests
	KubeletAuthorizationModeAlwaysAllow KubeletAuthorizationMode = "AlwaysAllow"
	// KubeletAuthorizationModeWebhook uses the SubjectAccessReview API to determine authorization
	KubeletAuthorizationModeWebhook KubeletAuthorizationMode = "Webhook"
)

type KubeletAuthorization struct {
	// mode is the authorization mode to apply to requests to the kubelet server.
	// Valid values are `AlwaysAllow` and `Webhook`.
	// Webhook mode uses the SubjectAccessReview API to determine authorization.
	// +optional
	Mode KubeletAuthorizationMode `json:"mode,omitempty"`

	// webhook contains settings related to Webhook authorization.
	// +optional
	Webhook KubeletWebhookAuthorization `json:"webhook"`
}

type KubeletWebhookAuthorization struct {
	// cacheAuthorizedTTL is the duration to cache 'authorized' responses from the
	// webhook authorizer.
	// +optional
	CacheAuthorizedTTL metav1.Duration `json:"cacheAuthorizedTTL,omitempty"`
	// cacheUnauthorizedTTL is the duration to cache 'unauthorized' responses from
	// the webhook authorizer.
	// +optional
	CacheUnauthorizedTTL metav1.Duration `json:"cacheUnauthorizedTTL,omitempty"`
}

type KubeletAuthentication struct {
	// x509 contains settings related to x509 client certificate authentication.
	// +optional
	X509 KubeletX509Authentication `json:"x509"`
	// webhook contains settings related to webhook bearer token authentication.
	// +optional
	Webhook KubeletWebhookAuthentication `json:"webhook"`
	// anonymous contains settings related to anonymous authentication.
	// +optional
	Anonymous KubeletAnonymousAuthentication `json:"anonymous"`
}

type KubeletX509Authentication struct {
	// clientCAFile is the path to a PEM-encoded certificate bundle. If set, any request
	// presenting a client certificate signed by one of the authorities in the bundle
	// is authenticated with a username corresponding to the CommonName,
	// and groups corresponding to the Organization in the client certificate.
	// +optional
	ClientCAFile string `json:"clientCAFile,omitempty"`
}

type KubeletWebhookAuthentication struct {
	// enabled allows bearer token authentication backed by the
	// tokenreviews.authentication.k8s.io API.
	// +optional
	Enabled *bool `json:"enabled,omitempty"`
	// cacheTTL enables caching of authentication results
	// +optional
	CacheTTL metav1.Duration `json:"cacheTTL,omitempty"`
}

type KubeletAnonymousAuthentication struct {
	// enabled allows anonymous requests to the kubelet server.
	// Requests that are not rejected by another authentication method are treated as
	// anonymous requests.
	// Anonymous requests have a username of `system:anonymous`, and a group name of
	// `system:unauthenticated`.
	// +optional
	Enabled *bool `json:"enabled,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SerializedNodeConfigSource allows us to serialize v1.NodeConfigSource.
// This type is used internally by the Kubelet for tracking checkpointed dynamic configs.
// It exists in the kubeletconfig API group because it is classified as a versioned input to the Kubelet.
type SerializedNodeConfigSource struct {
	metav1.TypeMeta `json:",inline"`
	// source is the source that we are serializing.
	// +optional
	Source v1.NodeConfigSource `json:"source,omitempty" protobuf:"bytes,1,opt,name=source"`
}

// MemoryReservation specifies the memory reservation of different types for each NUMA node
type MemoryReservation struct {
	NumaNode int32          `json:"numaNode"`
	Limits   v1.ResourceMap `json:"limits"`
}

// ShutdownGracePeriodByPodPriority specifies the shutdown grace period for Pods based on their associated priority class value
type ShutdownGracePeriodByPodPriority struct {
	// priority is the priority value associated with the shutdown grace period
	Priority int32 `json:"priority"`
	// shutdownGracePeriodSeconds is the shutdown grace period in seconds
	ShutdownGracePeriodSeconds int64 `json:"shutdownGracePeriodSeconds"`
}

type MemorySwapConfiguration struct {
	// swapBehavior configures swap memory available to container workloads. May be one of
	// "", "LimitedSwap": workload combined memory and swap usage cannot exceed pod memory limit
	// "UnlimitedSwap": workloads can use unlimited swap, up to the allocatable limit.
	// +featureGate=NodeSwap
	// +optional
	SwapBehavior string `json:"swapBehavior,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CredentialProviderConfig is the configuration containing information about
// each exec credential provider. Kubelet reads this configuration from disk and enables
// each provider as specified by the CredentialProvider type.
type CredentialProviderConfig struct {
	metav1.TypeMeta `json:",inline"`

	// providers is a list of credential provider plugins that will be enabled by the kubelet.
	// Multiple providers may match against a single image, in which case credentials
	// from all providers will be returned to the kubelet. If multiple providers are called
	// for a single image, the results are combined. If providers return overlapping
	// auth keys, the value from the provider earlier in this list is used.
	Providers []CredentialProvider `json:"providers"`
}

// CredentialProvider represents an exec plugin to be invoked by the kubelet. The plugin is only
// invoked when an image being pulled matches the images handled by the plugin (see matchImages).
type CredentialProvider struct {
	// name is the required name of the credential provider. It must match the name of the
	// provider executable as seen by the kubelet. The executable must be in the kubelet's
	// bin directory (set by the --image-credential-provider-bin-dir flag).
	Name string `json:"name"`

	// matchImages is a required list of strings used to match against images in order to
	// determine if this provider should be invoked. If one of the strings matches the
	// requested image from the kubelet, the plugin will be invoked and given a chance
	// to provide credentials. Images are expected to contain the registry domain
	// and URL path.
	//
	// Each entry in matchImages is a pattern which can optionally contain a port and a path.
	// Globs can be used in the domain, but not in the port or the path. Globs are supported
	// as subdomains like '*.k8s.io' or 'k8s.*.io', and top-level-domains such as 'k8s.*'.
	// Matching partial subdomains like 'app*.k8s.io' is also supported. Each glob can only match
	// a single subdomain segment, so *.io does not match *.k8s.io.
	//
	// A match exists between an image and a matchImage when all of the below are true:
	// - Both contain the same number of domain parts and each part matches.
	// - The URL path of an imageMatch must be a prefix of the target image URL path.
	// - If the imageMatch contains a port, then the port must match in the image as well.
	//
	// Example values of matchImages:
	//   - 123456789.dkr.ecr.us-east-1.amazonaws.com
	//   - *.azurecr.io
	//   - gcr.io
	//   - *.*.registry.io
	//   - registry.io:8080/path
	MatchImages []string `json:"matchImages"`

	// defaultCacheDuration is the default duration the plugin will cache credentials in-memory
	// if a cache duration is not provided in the plugin response. This field is required.
	DefaultCacheDuration *metav1.Duration `json:"defaultCacheDuration"`

	// Required input version of the exec CredentialProviderRequest. The returned CredentialProviderResponse
	// MUST use the same encoding version as the input. Current supported values are:
	// - credentialprovider.kubelet.k8s.io/v1beta1
	APIVersion string `json:"apiVersion"`

	// Arguments to pass to the command when executing it.
	// +optional
	Args []string `json:"args,omitempty"`

	// Env defines additional environment variables to expose to the process. These
	// are unioned with the host's environment, as well as variables client-go uses
	// to pass argument to the plugin.
	// +optional
	Env []ExecEnvVar `json:"env,omitempty"`
}

// ExecEnvVar is used for setting environment variables when executing an exec-based
// credential plugin.
type ExecEnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
