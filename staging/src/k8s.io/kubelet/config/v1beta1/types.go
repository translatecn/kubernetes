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

// 不同处理回环数据包的方式的枚举设置
const (
	HairpinVeth       = "hairpin-veth"       // 在相应的容器运行时中,在容器的 veth 接口上设置回环标志.
	PromiscuousBridge = "promiscuous-bridge" // 使容器的网桥处于混杂模式.这将强制容器接受回环数据包,即使网桥的端口上没有设置回环标志.
	HairpinNone       = "none"               // 以上两种方式都不使用.如果 kubelet 在此回环模式下启动,并且 kube-proxy 在 iptables 模式下运行,则容器网桥将丢弃回环数据包.
)

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

// KubeletConfiguration contains the configuration for  the Kubelet
type KubeletConfiguration struct {
	metav1.TypeMeta                `json:",inline"`
	EnableServer                   *bool                 `json:"enableServer,omitempty"`                   // 启用Kubelet的安全服务器默认: true
	StaticPodPath                  string                `json:"staticPodPath,omitempty"`                  // 静态pod的文件夹 默认: ""
	SyncFrequency                  metav1.Duration       `json:"syncFrequency,omitempty"`                  // 周期性全量同步容器、配置的间隔 默认: "1m"
	FileCheckFrequency             metav1.Duration       `json:"fileCheckFrequency,omitempty"`             // 静态pod文件检查周期 默认: "20s"
	HTTPCheckFrequency             metav1.Duration       `json:"httpCheckFrequency,omitempty"`             // 静态pod http 检查周期 默认: "20s"
	StaticPodURL                   string                `json:"staticPodURL,omitempty"`                   // 获取静态文件列表的地址 默认: ""
	StaticPodURLHeader             map[string][]string   `json:"staticPodURLHeader,omitempty"`             // 获取静态文件列表的地址,需要使用一些 HTTP 头部信息 默认: nil
	Address                        string                `json:"address,omitempty"`                        // kubelet https端口地址  默认 0.0.0.0
	Port                           int32                 `json:"port,omitempty"`                           // kubelet https端口,默认10250
	ReadOnlyPort                   int32                 `json:"readOnlyPort,omitempty"`                   // 0 禁用
	TLSCertFile                    string                `json:"tlsCertFile,omitempty"`                    // ca 证书,默认 空,没指定,会生成自谦的,保存在--cert-dir
	TLSPrivateKeyFile              string                `json:"tlsPrivateKeyFile,omitempty"`              // 私钥文件,默认 空
	TLSCipherSuites                []string              `json:"tlsCipherSuites,omitempty"`                // 服务器允许的密码套件列表.默认: nil
	TLSMinVersion                  string                `json:"tlsMinVersion,omitempty"`                  // tls 支持的最小版本  默认: ""
	RotateCertificates             bool                  `json:"rotateCertificates,omitempty"`             // ❓启用客户端证书轮换.Kubelet将从certificates.k8s请求一个新证书.这需要审批者批准证书签名请求.默认: false
	ServerTLSBootstrap             bool                  `json:"serverTLSBootstrap,omitempty"`             // ❓启用了服务器证书引导.在自签名服务器证书的情况下,Kubelet将从'certificates.k8s.io' API请求证书 默认: false
	Authentication                 KubeletAuthentication `json:"authentication"`                           // 对Kubelet服务器请求的认证 配置
	Authorization                  KubeletAuthorization  `json:"authorization"`                            // 对Kubelet服务器请求的授权 配置
	RegistryPullQPS                *int32                `json:"registryPullQPS,omitempty"`                // 每秒image最大拉取数量 默认: 5
	RegistryBurst                  int32                 `json:"registryBurst,omitempty"`                  // 镜像拉取突发大小（一段时间内允许创建的最大数）
	EventRecordQPS                 *int32                `json:"eventRecordQPS,omitempty"`                 // 每秒最大事件创建数量 默认: 5
	EventBurst                     int32                 `json:"eventBurst,omitempty"`                     // 事件创建突发大小(一段时间内允许创建的最大数) 默认10
	EnableDebuggingHandlers        *bool                 `json:"enableDebuggingHandlers,omitempty"`        // 为日志访问、容器命令的本地运行 启用服务器端点,包括执行、附加、日志和端口转发特性.默认: true
	EnableContentionProfiling      bool                  `json:"enableContentionProfiling,omitempty"`      // 如果enableDebuggingHandlers为true,则启用锁争用分析.默认: false
	HealthzPort                    *int32                `json:"healthzPort,omitempty"`                    // healthz 服务暴露端口 10248
	HealthzBindAddress             string                `json:"healthzBindAddress,omitempty"`             // healthz 服务暴露地址 127.0.0.1
	OOMScoreAdj                    *int32                `json:"oomScoreAdj,omitempty"`                    // kubelet oom 分数,默认: -999  [-1000, 1000]
	ClusterDomain                  string                `json:"clusterDomain,omitempty"`                  // 集群域名,默认 ""
	ClusterDNS                     []string              `json:"clusterDNS,omitempty"`                     // 逗号分隔的 DNS 服务器 IP 地址列表,kubelet 会使用	// 默认: nil
	StreamingConnectionIdleTimeout metav1.Duration       `json:"streamingConnectionIdleTimeout,omitempty"` // stream 在关闭前的最大空闲时间 默认: "4h"
	NodeStatusUpdateFrequency      metav1.Duration       `json:"nodeStatusUpdateFrequency,omitempty"`      // kubelet计算节点状态是否变化的频率 "10s"
	NodeStatusReportFrequency      metav1.Duration       `json:"nodeStatusReportFrequency,omitempty"`      // 节点没有变化时,状态报告频率.当启用租约时,检测到变化,立即上报,忽略这个参数 "5m"
	NodeLeaseDurationSeconds       int32                 `json:"nodeLeaseDurationSeconds,omitempty"`       // nodeLeaseDurationSeconds  Kubelet将在其相应的Lease上设置的持续时间. 	// 默认: 40
	ImageMinimumGCAge              metav1.Duration       `json:"imageMinimumGCAge,omitempty"`              // 每个回收镜像必须存活的时间 2m
	ImageGCHighThresholdPercent    *int32                `json:"imageGCHighThresholdPercent,omitempty"`    // 运行image GC的磁盘使用百分比.取值范围为[0,100],不启用image gcc回收,defau.
	ImageGCLowThresholdPercent     *int32                `json:"imageGCLowThresholdPercent,omitempty"`     // 在此之前从未运行image GC的磁盘使用百分比.要进行垃圾收集的磁盘使用率最低.取值必须在[0,100]范围内,且不能大于--image-gc-high-threshold   默认 80
	VolumeStatsAggPeriod           metav1.Duration       `json:"volumeStatsAggPeriod,omitempty"`           // 计算和缓存所有pod卷磁盘使用量的频率  默认 1m
	KubeletCgroups                 string                `json:"kubeletCgroups,omitempty"`                 // kubelet 使用的cgroup路径,默认 ""
	SystemCgroups                  string                `json:"systemCgroups,omitempty"`                  // 系统cgroups 是一个绝对名称,用于存放所有非内核进程,这些进程尚未在容器中运行.如果为空,则表示没有容器.回滚此标志需要重新启动系统.如果systemCgroups字段不为空,则必须指定cgroupRoot.默认值为"".
	CgroupRoot                     string                `json:"cgroupRoot,omitempty"`                     // CgroupRoot是用于pod的根cgroup如果启用了CgroupsPerQOS,则这是QoS cgroup层次结构的根.
	CgroupsPerQOS                  *bool                 `json:"cgroupsPerQOS,omitempty"`                  // 启用基于QoS的Cgroup层次结构:QoS类的顶级Cgroup,所有Burstable和bestefort pod都在其特定的顶级QoS Cgroup下.   默认true
	CgroupDriver                   string                `json:"cgroupDriver,omitempty"`                   // kubelet用来在主机上操作cgroups的驱动程序(cgroupfs或systemd)默认: "cgroupfs"
	CPUManagerPolicy               string                `json:"cpuManagerPolicy,omitempty"`               // 内存管理器 策略      k=v 默认: nil
	CPUManagerPolicyOptions        map[string]string     `json:"cpuManagerPolicyOptions,omitempty"`        // 内存管理器 策略配置项 k=v 默认: nil
	CPUManagerReconcilePeriod      metav1.Duration       `json:"cpuManagerReconcilePeriod,omitempty"`      // 内存管理器调谐周期 10s
	MemoryManagerPolicy            string                `json:"memoryManagerPolicy,omitempty"`            // 内存管理策略 默认: "none"
	//"restricted"策略会只允许容器在请求资源的最佳NUMA节点上运行.
	//"best-effort"策略会优先选择具有CPU和设备资源在NUMA节点上对齐的容器.
	//"none"策略表示拓扑管理器不会考虑容器在NUMA节点上的分配情况.
	//"single-numa-node"策略会只允许容器在单个NUMA节点上运行.
	TopologyManagerPolicy        string            `json:"topologyManagerPolicy,omitempty"`        // 策略名称,除了 "none" 之外的策略需要启用 TopologyManager 功能门控.一般都开启
	TopologyManagerScope         string            `json:"topologyManagerScope,omitempty"`         // 拓扑管理器请求和提示提供程序生成的拓扑提示的范围[pod、container]. 默认: "container"
	TopologyManagerPolicyOptions map[string]string `json:"topologyManagerPolicyOptions,omitempty"` // 一组key=value,它允许设置额外的选项来微调拓扑管理器策略的行为.	// 默认: nil
	QOSReserved                  map[string]string `json:"qosReserved,omitempty"`                  // 资源百分比预留,当前只支持memory,默认: nil
	RuntimeRequestTimeout        metav1.Duration   `json:"runtimeRequestTimeout,omitempty"`        //  pull, logs, exec and attach 请求超时时间   2m
	// "promiscuous-bridge"：使容器桥接器处于混杂模式.
	// "hairpin-veth"：在容器的veth接口上设置hairpin标志.
	// "none"：不进行任何操作.
	// 默认: "promiscuous-bridge"
	HairpinMode                               string                             `json:"hairpinMode,omitempty"`                               // Kubelet如何配置容器桥接以支持hairpin数据包
	MaxPods                                   int32                              `json:"maxPods,omitempty"`                                   // maxPods is the maximum 可以在Kubelet上运行的pod的数量. 默认: 110
	PodCIDR                                   string                             `json:"podCIDR,omitempty"`                                   // standalone 模式下podip的分配范围,集群模式下由控制器分配
	PodPidsLimit                              *int64                             `json:"podPidsLimit,omitempty"`                              // pod中pid的最大数目.默认: -1
	ResolverConfig                            *string                            `json:"resolvConf,omitempty"`                                // 容器dns解析配置/etc/resolv.conf
	RunOnce                                   bool                               `json:"runOnce,omitempty"`                                   // Kubelet 仅检查一次 API 服务器以获取 Pod,运行这些 Pod 并在完成后退出,除了静态 Pod 文件中指定的 Pod 之外默认: false
	CPUCFSQuota                               *bool                              `json:"cpuCFSQuota,omitempty"`                               // 指定了CPU限制的容器,启用CPU CFS配额 默认: true
	CPUCFSQuotaPeriod                         *metav1.Duration                   `json:"cpuCFSQuotaPeriod,omitempty"`                         // CPU CFS配额周期的值,即cpu.cfs_period_us.该值必须在1毫秒和1秒之间（包括1毫秒和1秒）.要求启用CustomCPUCFSQuotaPeriod功能门控. 默认: "100ms"
	NodeStatusMaxImages                       *int32                             `json:"nodeStatusMaxImages,omitempty"`                       // 节点status 存储的最大image 数量 默认: 50
	MaxOpenFiles                              int64                              `json:"maxOpenFiles,omitempty"`                              // Kubelet进程可以打开的文件数量.1000000
	ContentType                               string                             `json:"contentType,omitempty"`                               // 发送到 apiserver 的消息格式.默认: "application/vnd.kubernetes.protobuf"
	KubeAPIQPS                                *int32                             `json:"kubeAPIQPS,omitempty"`                                // 与Kubernetes API服务器通信时使用的每秒请求数.默认: 5
	KubeAPIBurst                              int32                              `json:"kubeAPIBurst,omitempty"`                              // Kubernetes API服务器通信时允许的突发请求数.	默认: 10
	SerializeImagePulls                       *bool                              `json:"serializeImagePulls,omitempty"`                       // 串行化拉取镜像.我们建议在运行Docker版本小于1.9或使用Aufs存储后端的节点上不要更改默认值.默认: true
	EvictionHard                              map[string]string                  `json:"evictionHard,omitempty"`                              // 硬驱逐阈值		    {"memory.available":  "100Mi","nodefs.available":  "10%","nodefs.inodesFree": "5%","imagefs.available": "15%"}
	EvictionSoft                              map[string]string                  `json:"evictionSoft,omitempty"`                              // 软驱逐阈值		    {"memory.available": "300Mi"}
	EvictionSoftGracePeriod                   map[string]string                  `json:"evictionSoftGracePeriod,omitempty"`                   // 每个软驱逐信号的宽限期 {"memory.available": "30s"}
	EvictionPressureTransitionPeriod          metav1.Duration                    `json:"evictionPressureTransitionPeriod,omitempty"`          // 退出驱逐压力状态之前必须等待的持续时间.默认: "5m"
	EvictionMaxPodGracePeriod                 int32                              `json:"evictionMaxPodGracePeriod,omitempty"`                 // 在满足软驱逐阈值时终止Pod时使用的最大允许宽限期（以秒为单位）,默认0s
	EvictionMinimumReclaim                    map[string]string                  `json:"evictionMinimumReclaim,omitempty"`                    // 进行资源回收的资源的最小回收量, {"imagefs.available": "2Gi"}	默认: nil
	PodsPerCore                               int32                              `json:"podsPerCore,omitempty"`                               // 每个pod使用的最大core,默认0,不限制
	EnableControllerAttachDetach              *bool                              `json:"enableControllerAttachDetach,omitempty"`              // 使Attach/Detach控制器能够管理计划到该节点的卷的附加/分离,并禁用kubelet执行任何附加/分离操作. 注意:kubelet不支持附加/分离CSI卷,所以这个选项需要为true. 默认: true
	ProtectKernelDefaults                     bool                               `json:"protectKernelDefaults,omitempty"`                     // 如果 protectKernel默认s 为 true,则会导致 Kubelet 在内核标志不符合其预期时出错.否则,Kubelet 将尝试修改内核标志以匹配其预期. 默认: false
	MakeIPTablesUtilChains                    *bool                              `json:"makeIPTablesUtilChains,omitempty"`                    // 如果为true, kubelet将确保主机上存在iptables实用程序规则.这些规则将作为各种组件的实用工具,例如kube-proxy.规则将基于IPTablesMasqueradeBit和IPTablesDropBit创建. 默认: true
	IPTablesMasqueradeBit                     *int32                             `json:"iptablesMasqueradeBit,omitempty"`                     // SNAT标记的iptables fwmark空间的位.默认: 14
	IPTablesDropBit                           *int32                             `json:"iptablesDropBit,omitempty"`                           // iptablesDropBit是iptables的fwmark空间的位,用于标记丢弃报文. 取值范围为[0,31].必须与其他标记位不同. 默认: 15
	FeatureGates                              map[string]bool                    `json:"featureGates,omitempty"`                              // 功能名称到启用或禁用实验性功能的工具的映射.
	FailSwapOn                                *bool                              `json:"failSwapOn,omitempty"`                                // 告诉Kubelet,如果在节点上启用了swap,则启动失败.默认为true
	MemorySwap                                MemorySwapConfiguration            `json:"memorySwap,omitempty"`                                // 配置容器工作负载可用的交换内存.	+featureGate=NodeSwap
	ContainerLogMaxSize                       string                             `json:"containerLogMaxSize,omitempty"`                       // 容器日志最大大小,默认: "10Mi"
	ContainerLogMaxFiles                      *int32                             `json:"containerLogMaxFiles,omitempty"`                      // 容器日志最多个数,默认5
	ConfigMapAndSecretChangeDetectionStrategy ResourceChangeDetectionStrategy    `json:"configMapAndSecretChangeDetectionStrategy,omitempty"` // ConfigMap和Secret获取方式,默认watch
	SystemReserved                            map[string]string                  `json:"systemReserved,omitempty"`                            // 预留资源,只支持  cpu=200m,memory=150G,ephemeral-storage=1G,pid=100 默认: nil
	KubeReserved                              map[string]string                  `json:"kubeReserved,omitempty"`                              // 预留资源,只支持  cpu=200m,memory=150G,ephemeral-storage=1G,pid=100 默认: nil
	ReservedSystemCPUs                        string                             `json:"reservedSystemCPUs,omitempty"`                        // 为主机级系统线程和与Kubernetes相关的线程保留的CPU列表
	ShowHiddenMetricsForVersion               string                             `json:"showHiddenMetricsForVersion,omitempty"`               // 需要显示?版本已经隐藏的指标
	SystemReservedCgroup                      string                             `json:"systemReservedCgroup,omitempty"`                      // 强制执行Kubernetes节点系统守护程序的systemReserved计算资源预留的顶级CGroup的绝对名称.
	KubeReservedCgroup                        string                             `json:"kubeReservedCgroup,omitempty"`                        // 强制执行Kubernetes节点系统守护程序的KubeReserved计算资源预留的顶级CGroup的绝对名称.
	EnforceNodeAllocatable                    []string                           `json:"enforceNodeAllocatable,omitempty"`                    // Kubelet需要执行的各种节点可分配强制措施`none`, `pods`,`system-reserved` and `kube-reserved`..cgroupsPerQPS设置前提下, system-reserved:systemReservedCgroup   , kube-reserved:kubeReservedCgroup 默认: ["pods"]
	AllowedUnsafeSysctls                      []string                           `json:"allowedUnsafeSysctls,omitempty"`                      // 被允许的 sysctl 不安全指令;这些系统设置了名称空间,但默认情况下不允许. `kernel.shm*`, `kernel.msg*`, `kernel.sem`, `fs.mqueue.*`, and `net.*`.默认: []
	VolumePluginDir                           string                             `json:"volumePluginDir,omitempty"`                           // 搜索其他第三方卷插件的完整目录路径.该目录下可能包含用于kubernetes的自定义卷插件,这些插件可以通过该目录进行加载和使用.	// 默认: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
	ProviderID                                string                             `json:"providerID,omitempty"`                                // 外部提供商(即云提供商)可以用来识别特定节点的实例的唯一ID. 默认: ""
	KernelMemcgNotification                   bool                               `json:"kernelMemcgNotification,omitempty"`                   // 如果为true,将与内核memcg通知集成,以确定是否超过内存阈值.默认: false
	Logging                                   logsapi.LoggingConfiguration       `json:"logging,omitempty"`                                   // 日志格式,
	EnableSystemLogHandler                    *bool                              `json:"enableSystemLogHandler,omitempty"`                    // 是否允许系统日志通过host:port/logs/ 访问,默认: true
	ShutdownGracePeriod                       metav1.Duration                    `json:"shutdownGracePeriod,omitempty"`                       // 节点关闭时,容器优雅关闭等待的时间默认: "0s"	+featureGate=GracefulNodeShutdown
	ShutdownGracePeriodCriticalPods           metav1.Duration                    `json:"shutdownGracePeriodCriticalPods,omitempty"`           // 指定分配给节点优雅关闭等待的时间,默认0s.if ShutdownGracePeriod=30s, and ShutdownGracePeriodCriticalPods=10s, 在 node 关闭期间,前20秒将保留用于优雅地终止正常pod,最后10秒将保留用于终止关键pod.+featureGate=GracefulNodeShutdown
	ShutdownGracePeriodByPodPriority          []ShutdownGracePeriodByPodPriority `json:"shutdownGracePeriodByPodPriority,omitempty"`          // 基于优先级类别值的Pod的关机宽限期.		+featureGate=GracefulNodeShutdownBasedOnPodPriority
	ReservedMemory                            []MemoryReservation                `json:"reservedMemory,omitempty"`                            // 每个numa 节点, 限制的资源  默认: nil
	EnableProfilingHandler                    *bool                              `json:"enableProfilingHandler,omitempty"`                    // 是否启用prof handler   host:port/debug/pprof/  默认: true
	EnableDebugFlagsHandler                   *bool                              `json:"enableDebugFlagsHandler,omitempty"`                   // 是否启用flags handler  host:port/debug/flags/v 默认: true
	SeccompDefault                            *bool                              `json:"seccompDefault,omitempty"`                            // 为所有工作负载设置Seccomp 配置文件.默认: false
	MemoryThrottlingFactor                    *float64                           `json:"memoryThrottlingFactor,omitempty"`                    // 设置cgroupv2内存时,该因子乘以内存限制或节点可分配内存.默认: 0.8	+featureGate=MemoryQoS
	RegisterWithTaints                        []v1.Taint                         `json:"registerWithTaints,omitempty"`                        // 自动注册时,附加的污点默认: nil
	RegisterNode                              *bool                              `json:"registerNode,omitempty"`                              // 是否允许自动注册到apiserver  默认: true
	Tracing                                   *tracingapi.TracingConfiguration   `json:"tracing,omitempty"`                                   // 指定OpenTelemetry跟踪客户端的版本化配置.+featureGate=KubeletTracing
	LocalStorageCapacityIsolation             *bool                              `json:"localStorageCapacityIsolation,omitempty"`             // 本地临时存储隔离功能.默认设置为 true.此功能允许用户为容器的临时存储设置 requests limit
}

type KubeletAuthorizationMode string

const (
	KubeletAuthorizationModeAlwaysAllow KubeletAuthorizationMode = "AlwaysAllow"
	KubeletAuthorizationModeWebhook     KubeletAuthorizationMode = "Webhook" // 它会将请求发送到授权Webhook,由Webhook根据自定义逻辑进行授权验证.
)

type KubeletAuthorization struct {
	Mode    KubeletAuthorizationMode    `json:"mode,omitempty"`
	Webhook KubeletWebhookAuthorization `json:"webhook"`
}

type KubeletWebhookAuthorization struct {
	CacheAuthorizedTTL   metav1.Duration `json:"cacheAuthorizedTTL,omitempty"`   // 授权成功结果缓存时间
	CacheUnauthorizedTTL metav1.Duration `json:"cacheUnauthorizedTTL,omitempty"` // 授权失败结果缓存时间
}

type KubeletAuthentication struct {
	X509      KubeletX509Authentication      `json:"x509"`      // kubelet 与客户端 通信的证书配置
	Webhook   KubeletWebhookAuthentication   `json:"webhook"`   // bearer token 配置
	Anonymous KubeletAnonymousAuthentication `json:"anonymous"` // 包含与匿名身份验证相关的设置,通过启用匿名身份验证,可以允许未经身份验证的用户以匿名身份访问和使用Kubernetes集群的资源.
}

type KubeletX509Authentication struct {
	ClientCAFile string `json:"clientCAFile,omitempty"`
}

type KubeletWebhookAuthentication struct {
	Enabled  *bool           `json:"enabled,omitempty"` // 是否允许使用基于Bearer Token的身份验证
	CacheTTL metav1.Duration `json:"cacheTTL,omitempty"`
}

type KubeletAnonymousAuthentication struct {
	Enabled *bool `json:"enabled,omitempty"` // 是否允许匿名用户访问   匿名请求的用户名为system:anonymous,组名为system:unauthenticated.
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type SerializedNodeConfigSource struct {
	metav1.TypeMeta `json:",inline"`
	Source          v1.NodeConfigSource `json:"source,omitempty" protobuf:"bytes,1,opt,name=source"`
}

// MemoryReservation 指定每个numa 节点, 限制的资源
type MemoryReservation struct {
	NumaNode int32          `json:"numaNode"`
	Limits   v1.ResourceMap `json:"limits"`
}

type ShutdownGracePeriodByPodPriority struct {
	Priority                   int32 `json:"priority"`
	ShutdownGracePeriodSeconds int64 `json:"shutdownGracePeriodSeconds"`
}

type MemorySwapConfiguration struct {
	//swapBehavior 配置了容器工作负载可用的交换内存.它可以是以下之一：
	//- ""：工作负载的内存和交换内存使用总和不能超过 Pod 的内存限制.
	//- "LimitedSwap"：工作负载的内存和交换内存使用总和不能超过 Pod 的内存限制.
	//- "UnlimitedSwap"：工作负载可以使用无限制的交换内存,但不能超过可分配的限制.
	//
	//此功能需要使用 NodeSwap 的 feature gate.
	SwapBehavior string `json:"swapBehavior,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type CredentialProviderConfig struct {
	metav1.TypeMeta `json:",inline"`
	//providers 是 kubelet 将启用的凭据提供程序插件列表.
	//多个提供程序可以匹配单个镜像,此时所有提供程序的凭据将返回给 kubelet.
	//如果为单个镜像调用多个提供程序,则将合并结果.如果提供程序返回重叠的认证密钥,则使用此列表中较早的提供程序的值.
	Providers []CredentialProvider `json:"providers"`
}

// CredentialProvider represents an exec plugin to be invoked by the kubelet. The plugin is only
// invoked when an image being pulled matches the images handled by the plugin (see matchImages).
type CredentialProvider struct {
	// name 是凭据提供程序的必需名称.
	// 它必须与 kubelet 可见的提供程序可执行文件的名称匹配
	// 该可执行文件必须位于 kubelet 的 bin 目录中（通过 --image-credential-provider-bin-dir 标志设置）.
	Name string `json:"name"`
	// Example values of matchImages:
	//   - 123456789.dkr.ecr.us-east-1.amazonaws.com
	//   - *.azurecr.io
	//   - gcr.io
	//   - *.*.registry.io
	//   - registry.io:8080/path
	MatchImages          []string         `json:"matchImages"`          // 用于与镜像进行匹配,以确定是否应调用此提供程序.
	DefaultCacheDuration *metav1.Duration `json:"defaultCacheDuration"` // 凭证缓存时间

	// exec CredentialProviderRequest 的所需输入版本.返回的 CredentialProviderResponse 必须使用与输入相同的编码版本.当前支持的值有：
	// - credentialprovider.kubelet.k8s.io/v1beta1
	APIVersion string       `json:"apiVersion"`
	Args       []string     `json:"args,omitempty"`
	Env        []ExecEnvVar `json:"env,omitempty"`
}

type ExecEnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
