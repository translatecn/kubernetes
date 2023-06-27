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
	metav1.TypeMeta    `json:",inline"`
	EnableServer       *bool               `json:"enableServer,omitempty"`       // 启用Kubelet的安全服务器Default: true
	StaticPodPath      string              `json:"staticPodPath,omitempty"`      // 静态pod的文件夹 Default: ""
	SyncFrequency      metav1.Duration     `json:"syncFrequency,omitempty"`      // 周期性全量同步容器、配置的间隔 Default: "1m"
	FileCheckFrequency metav1.Duration     `json:"fileCheckFrequency,omitempty"` // 静态pod文件检查周期 Default: "20s"
	HTTPCheckFrequency metav1.Duration     `json:"httpCheckFrequency,omitempty"` // 静态pod http 检查周期 Default: "20s"
	StaticPodURL       string              `json:"staticPodURL,omitempty"`       // 获取静态文件列表的地址 Default: ""
	StaticPodURLHeader map[string][]string `json:"staticPodURLHeader,omitempty"` // 获取静态文件列表的地址,需要使用一些 HTTP 头部信息 Default: nil
	Address            string              `json:"address,omitempty"`            // kubelet https端口地址  默认 0.0.0.0
	Port               int32               `json:"port,omitempty"`               // kubelet https端口,默认10250
	ReadOnlyPort       int32               `json:"readOnlyPort,omitempty"`       // 0 禁用
	TLSCertFile        string              `json:"tlsCertFile,omitempty"`        // ca 证书,默认 空,没指定,会生成自谦的,保存在--cert-dir
	TLSPrivateKeyFile  string              `json:"tlsPrivateKeyFile,omitempty"`  // 私钥文件,默认 空
	TLSCipherSuites    []string            `json:"tlsCipherSuites,omitempty"`    // 服务器允许的密码套件列表.Default: nil
	TLSMinVersion      string              `json:"tlsMinVersion,omitempty"`      // tls 支持的最小版本  Default: ""
	RotateCertificates bool                `json:"rotateCertificates,omitempty"` // 启用客户端证书轮换.Kubelet将从certificates.k8s请求一个新证书.这需要审批者批准证书签名请求.Default: false

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
	EventBurst                int32  `json:"eventBurst,omitempty"`
	EnableDebuggingHandlers   *bool  `json:"enableDebuggingHandlers,omitempty"`   // 为日志访问、容器命令的本地运行 启用服务器端点,包括执行、附加、日志和端口转发特性.Default: true
	EnableContentionProfiling bool   `json:"enableContentionProfiling,omitempty"` // 如果enableDebuggingHandlers为true,则启用锁争用分析.Default: false
	HealthzPort               *int32 `json:"healthzPort,omitempty"`               // healthz 服务暴露端口 10248
	HealthzBindAddress        string `json:"healthzBindAddress,omitempty"`        // healthz 服务暴露地址 127.0.0.1
	OOMScoreAdj               *int32 `json:"oomScoreAdj,omitempty"`               // kubelet oom 分数,Default: -999  [-1000, 1000]
	// clusterDomain is the DNS domain for this cluster. If set, kubelet will
	// configure all containers to search this domain in addition to the
	// host's search domains.
	// Default: ""
	// +optional
	ClusterDomain                  string          `json:"clusterDomain,omitempty"`
	ClusterDNS                     []string        `json:"clusterDNS,omitempty"`                     // 逗号分隔的 DNS 服务器 IP 地址列表,kubelet 会使用	// Default: nil
	StreamingConnectionIdleTimeout metav1.Duration `json:"streamingConnectionIdleTimeout,omitempty"` // stream 在关闭前的最大空闲时间 Default: "4h"
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
	CPUCFSQuota                               *bool                              `json:"cpuCFSQuota,omitempty"`
	CPUCFSQuotaPeriod                         *metav1.Duration                   `json:"cpuCFSQuotaPeriod,omitempty"`                         // CPU CFS配额周期的值,即cpu.cfs_period_us.该值必须在1毫秒和1秒之间（包括1毫秒和1秒）.要求启用CustomCPUCFSQuotaPeriod功能门控. Default: "100ms"
	NodeStatusMaxImages                       *int32                             `json:"nodeStatusMaxImages,omitempty"`                       // 节点status 存储的最大image 数量 Default: 50
	MaxOpenFiles                              int64                              `json:"maxOpenFiles,omitempty"`                              // Kubelet进程可以打开的文件数量.1000000
	ContentType                               string                             `json:"contentType,omitempty"`                               // 发送到 apiserver 的消息格式.Default: "application/vnd.kubernetes.protobuf"
	KubeAPIQPS                                *int32                             `json:"kubeAPIQPS,omitempty"`                                // 与Kubernetes API服务器通信时使用的每秒请求数.Default: 5
	KubeAPIBurst                              int32                              `json:"kubeAPIBurst,omitempty"`                              // Kubernetes API服务器通信时允许的突发请求数.	Default: 10
	SerializeImagePulls                       *bool                              `json:"serializeImagePulls,omitempty"`                       // 串行化拉取镜像.我们建议在运行Docker版本小于1.9或使用Aufs存储后端的节点上不要更改默认值.Default: true
	EvictionHard                              map[string]string                  `json:"evictionHard,omitempty"`                              // 硬驱逐阈值		    {"memory.available":  "100Mi","nodefs.available":  "10%","nodefs.inodesFree": "5%","imagefs.available": "15%"}
	EvictionSoft                              map[string]string                  `json:"evictionSoft,omitempty"`                              // 软驱逐阈值		    {"memory.available": "300Mi"}
	EvictionSoftGracePeriod                   map[string]string                  `json:"evictionSoftGracePeriod,omitempty"`                   // 每个软驱逐信号的宽限期 {"memory.available": "30s"}
	EvictionPressureTransitionPeriod          metav1.Duration                    `json:"evictionPressureTransitionPeriod,omitempty"`          // 退出驱逐压力状态之前必须等待的持续时间.Default: "5m"
	EvictionMaxPodGracePeriod                 int32                              `json:"evictionMaxPodGracePeriod,omitempty"`                 // 在满足软驱逐阈值时终止Pod时使用的最大允许宽限期（以秒为单位）,默认0s
	EvictionMinimumReclaim                    map[string]string                  `json:"evictionMinimumReclaim,omitempty"`                    // 进行资源回收的资源的最小回收量, {"imagefs.available": "2Gi"}	Default: nil
	PodsPerCore                               int32                              `json:"podsPerCore,omitempty"`                               // 每个pod使用的最大core,默认0,不限制
	EnableControllerAttachDetach              *bool                              `json:"enableControllerAttachDetach,omitempty"`              // 使Attach/Detach控制器能够管理计划到该节点的卷的附加/分离,并禁用kubelet执行任何附加/分离操作. 注意:kubelet不支持附加/分离CSI卷,所以这个选项需要为true. Default: true
	ProtectKernelDefaults                     bool                               `json:"protectKernelDefaults,omitempty"`                     // 如果 protectKernelDefaults 为 true,则会导致 Kubelet 在内核标志不符合其预期时出错.否则,Kubelet 将尝试修改内核标志以匹配其预期. Default: false
	MakeIPTablesUtilChains                    *bool                              `json:"makeIPTablesUtilChains,omitempty"`                    // 如果为true, kubelet将确保主机上存在iptables实用程序规则.这些规则将作为各种组件的实用工具,例如kube-proxy.规则将基于IPTablesMasqueradeBit和IPTablesDropBit创建. Default: true
	IPTablesMasqueradeBit                     *int32                             `json:"iptablesMasqueradeBit,omitempty"`                     // SNAT标记的iptables fwmark空间的位.Default: 14
	IPTablesDropBit                           *int32                             `json:"iptablesDropBit,omitempty"`                           // iptablesDropBit是iptables的fwmark空间的位,用于标记丢弃报文. 取值范围为[0,31].必须与其他标记位不同. Default: 15
	FeatureGates                              map[string]bool                    `json:"featureGates,omitempty"`                              // 功能名称到启用或禁用实验性功能的工具的映射.
	FailSwapOn                                *bool                              `json:"failSwapOn,omitempty"`                                // 告诉Kubelet,如果在节点上启用了swap,则启动失败.默认为true
	MemorySwap                                MemorySwapConfiguration            `json:"memorySwap,omitempty"`                                // 配置容器工作负载可用的交换内存.	+featureGate=NodeSwap
	ContainerLogMaxSize                       string                             `json:"containerLogMaxSize,omitempty"`                       // 容器日志最大大小,Default: "10Mi"
	ContainerLogMaxFiles                      *int32                             `json:"containerLogMaxFiles,omitempty"`                      // 容器日志最多个数,默认5
	ConfigMapAndSecretChangeDetectionStrategy ResourceChangeDetectionStrategy    `json:"configMapAndSecretChangeDetectionStrategy,omitempty"` // ConfigMap和Secret获取方式,默认watch
	SystemReserved                            map[string]string                  `json:"systemReserved,omitempty"`                            // 预留资源,只支持  cpu=200m,memory=150G,ephemeral-storage=1G,pid=100 Default: nil
	KubeReserved                              map[string]string                  `json:"kubeReserved,omitempty"`                              // 预留资源,只支持  cpu=200m,memory=150G,ephemeral-storage=1G,pid=100 Default: nil
	ReservedSystemCPUs                        string                             `json:"reservedSystemCPUs,omitempty"`                        // 为主机级系统线程和与Kubernetes相关的线程保留的CPU列表
	ShowHiddenMetricsForVersion               string                             `json:"showHiddenMetricsForVersion,omitempty"`               // 需要显示?版本已经隐藏的指标
	SystemReservedCgroup                      string                             `json:"systemReservedCgroup,omitempty"`                      // 强制执行Kubernetes节点系统守护程序的systemReserved计算资源预留的顶级CGroup的绝对名称.
	KubeReservedCgroup                        string                             `json:"kubeReservedCgroup,omitempty"`                        // 强制执行Kubernetes节点系统守护程序的KubeReserved计算资源预留的顶级CGroup的绝对名称.
	EnforceNodeAllocatable                    []string                           `json:"enforceNodeAllocatable,omitempty"`                    // Kubelet需要执行的各种节点可分配强制措施`none`, `pods`,`system-reserved` and `kube-reserved`..cgroupsPerQPS设置前提下, system-reserved:systemReservedCgroup   , kube-reserved:kubeReservedCgroup Default: ["pods"]
	AllowedUnsafeSysctls                      []string                           `json:"allowedUnsafeSysctls,omitempty"`                      // 被允许的 sysctl 不安全指令;这些系统设置了名称空间,但默认情况下不允许. `kernel.shm*`, `kernel.msg*`, `kernel.sem`, `fs.mqueue.*`, and `net.*`.Default: []
	VolumePluginDir                           string                             `json:"volumePluginDir,omitempty"`                           // 搜索其他第三方卷插件的完整目录路径.该目录下可能包含用于kubernetes的自定义卷插件,这些插件可以通过该目录进行加载和使用.	// Default: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
	ProviderID                                string                             `json:"providerID,omitempty"`                                // 外部提供商(即云提供商)可以用来识别特定节点的实例的唯一ID. Default: ""
	KernelMemcgNotification                   bool                               `json:"kernelMemcgNotification,omitempty"`                   // 如果为true,将与内核memcg通知集成,以确定是否超过内存阈值.Default: false
	Logging                                   logsapi.LoggingConfiguration       `json:"logging,omitempty"`                                   // 日志格式,
	EnableSystemLogHandler                    *bool                              `json:"enableSystemLogHandler,omitempty"`                    // 是否允许系统日志通过host:port/logs/ 访问,Default: true
	ShutdownGracePeriod                       metav1.Duration                    `json:"shutdownGracePeriod,omitempty"`                       // 节点关闭时,容器优雅关闭等待的时间Default: "0s"	+featureGate=GracefulNodeShutdown
	ShutdownGracePeriodCriticalPods           metav1.Duration                    `json:"shutdownGracePeriodCriticalPods,omitempty"`           // 指定分配给节点优雅关闭等待的时间,默认0s.if ShutdownGracePeriod=30s, and ShutdownGracePeriodCriticalPods=10s, 在 node 关闭期间,前20秒将保留用于优雅地终止正常pod,最后10秒将保留用于终止关键pod.+featureGate=GracefulNodeShutdown
	ShutdownGracePeriodByPodPriority          []ShutdownGracePeriodByPodPriority `json:"shutdownGracePeriodByPodPriority,omitempty"`          // 基于优先级类别值的Pod的关机宽限期.		+featureGate=GracefulNodeShutdownBasedOnPodPriority
	ReservedMemory                            []MemoryReservation                `json:"reservedMemory,omitempty"`                            // 每个numa 节点, 限制的资源  Default: nil
	EnableProfilingHandler                    *bool                              `json:"enableProfilingHandler,omitempty"`                    // 是否启用prof handler   host:port/debug/pprof/  Default: true
	EnableDebugFlagsHandler                   *bool                              `json:"enableDebugFlagsHandler,omitempty"`                   // 是否启用flags handler  host:port/debug/flags/v Default: true
	SeccompDefault                            *bool                              `json:"seccompDefault,omitempty"`                            // 为所有工作负载设置Seccomp 配置文件.Default: false
	MemoryThrottlingFactor                    *float64                           `json:"memoryThrottlingFactor,omitempty"`                    // 设置cgroupv2内存时,该因子乘以内存限制或节点可分配内存.Default: 0.8	+featureGate=MemoryQoS
	RegisterWithTaints                        []v1.Taint                         `json:"registerWithTaints,omitempty"`                        // 自动注册时,附加的污点Default: nil
	RegisterNode                              *bool                              `json:"registerNode,omitempty"`                              // 是否允许自动注册到apiserver  Default: true
	Tracing                                   *tracingapi.TracingConfiguration   `json:"tracing,omitempty"`                                   // 指定OpenTelemetry跟踪客户端的版本化配置.+featureGate=KubeletTracing

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

// MemoryReservation 指定每个numa 节点, 限制的资源
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

type ExecEnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
