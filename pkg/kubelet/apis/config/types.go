/*
Copyright 2015 The Kubernetes Authors.

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

package config

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

// Enum settings for different strategies of kubelet managers.
const (
	// GetChangeDetectionStrategy is a mode in which kubelet fetches
	// necessary objects directly from apiserver.
	GetChangeDetectionStrategy ResourceChangeDetectionStrategy = "Get"
	// TTLCacheChangeDetectionStrategy is a mode in which kubelet uses
	// ttl cache for object directly fetched from apiserver.
	TTLCacheChangeDetectionStrategy ResourceChangeDetectionStrategy = "Cache"
	// WatchChangeDetectionStrategy is a mode in which kubelet uses
	// watches to observe changes to objects that are in its interest.
	WatchChangeDetectionStrategy ResourceChangeDetectionStrategy = "Watch"
	// RestrictedTopologyManagerPolicy is a mode in which kubelet only allows
	// pods with optimal NUMA node alignment for requested resources
	RestrictedTopologyManagerPolicy = "restricted"
	// BestEffortTopologyManagerPolicy is a mode in which kubelet will favour
	// pods with NUMA alignment of CPU and device resources.
	BestEffortTopologyManagerPolicy = "best-effort"
	// NoneTopologyManagerPolicy is a mode in which kubelet has no knowledge
	// of NUMA alignment of a pod's CPU and device resources.
	NoneTopologyManagerPolicy = "none"
	// SingleNumaNodeTopologyManagerPolicy is a mode in which kubelet only allows
	// pods with a single NUMA alignment of CPU and device resources.
	SingleNumaNodeTopologyManagerPolicy = "single-numa-node"
	// ContainerTopologyManagerScope represents that
	// topology policy is applied on a per-container basis.
	ContainerTopologyManagerScope = "container"
	// PodTopologyManagerScope represents that
	// topology policy is applied on a per-pod basis.
	PodTopologyManagerScope = "pod"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// KubeletConfiguration contains the configuration for the Kubelet
type KubeletConfiguration struct {
	metav1.TypeMeta

	// enableServer enables Kubelet's secured server.
	// Note: Kubelet's insecure port is controlled by the readOnlyPort option.
	EnableServer       bool
	StaticPodPath      string              // 包含要运行的静态pod文件的目录路径，或单个静态pod文件的路径。以点开头的文件将被忽略。
	SyncFrequency      metav1.Duration     // 同步运行容器和配置之间的最大时间间隔。
	FileCheckFrequency metav1.Duration     // 检查配置文件以获取新数据之间的持续时间。
	HTTPCheckFrequency metav1.Duration     // 检查http以获取新数据的时间
	StaticPodURL       string              // 用于从某个地址获取要运行的静态pod。
	StaticPodURLHeader map[string][]string `datapolicy:"token"` // 在访问提供给--manifest-url的URL时要使用的逗号分隔的HTTP标头列表。具有相同名称的多个标头将按提供的相同顺序添加。可以重复使用此标志。
	Address            string              // Kubelet要服务的IP地址（设置为“0.0.0.0”或“::”以在所有接口和IP族上进行侦听）
	Port               int32               // Kubelet要服务的端口。
	ReadOnlyPort       int32               // Kubelet要在其上提供只读端口，没有身份验证/授权（设置为0以禁用）
	// volumePluginDir is the full path of the directory in which to search
	// for additional third party volume plugins.
	VolumePluginDir string
	// providerID, if set, sets the unique id of the instance that an external provider (i.e. cloudprovider)
	// can use to identify a specific node
	ProviderID string

	TLSCertFile        string // 包含用于提供HTTPS的x509证书的文件（如果有中间证书，则连接在服务器证书之后）。如果未提供--tls-cert-file和--tls-private-key-file，则会为公共地址生成自签名证书和密钥，并保存到传递给--cert-dir的目录中。
	TLSPrivateKeyFile  string // 包含与--tls-cert-file匹配的x509私钥的文件。
	TLSCipherSuites    []string
	TLSMinVersion      string
	RotateCertificates bool // <警告：Beta功能>通过在证书过期接近时,从kube-apiserver请求新证书，自动轮换kubelet客户端证书。

	ServerTLSBootstrap bool // 通过在证书过期接近时,从kube-apiserver请求新证书来自动请求和轮换kubelet服务证书。需要启用RotateKubeletServerCertificate 开关，并批准提交的CSR对象。

	Authentication  KubeletAuthentication
	Authorization   KubeletAuthorization
	RegistryPullQPS int32 // 如果> 0，则将注册表拉取QPS限制为此值。如果为0，则无限制。
	RegistryBurst   int32 // 突发式拉取的最大大小，临时允许拉取突发到此数字，同时仍不超过registry-qps。仅在--registry-qps> 0时使用。
	EventRecordQPS  int32 // 限制事件创建的QPS。数字必须>= 0。如果为0，将使用DefaultQPS：5。
	EventBurst      int32 // 突发式事件记录的最大大小，临时允许事件记录突发到此数字，同时仍不超过event-qps。数字必须>= 0。如果为0，将使用DefaultBurst：10。

	EnableDebuggingHandlers bool // 启用用于日志收集和本地运行容器和命令的服务器端点。
	// enableContentionProfiling enables lock contention profiling, if enableDebuggingHandlers is true.
	EnableContentionProfiling bool
	HealthzPort               int32
	HealthzBindAddress        string
	// oomScoreAdj is The oom-score-adj value for kubelet process. Values
	// must be within the range [-1000, 1000].
	OOMScoreAdj int32
	// clusterDomain is the DNS domain for this cluster. If set, kubelet will
	// configure all containers to search this domain in addition to the
	// host's search domains.
	ClusterDomain string
	// clusterDNS is a list of IP addresses for a cluster DNS server. If set,
	// kubelet will configure all containers to use this for DNS resolution
	// instead of the host's DNS servers.
	ClusterDNS []string
	// streamingConnectionIdleTimeout is the maximum time a streaming connection
	// can be idle before the connection is automatically closed.
	StreamingConnectionIdleTimeout metav1.Duration
	// nodeStatusUpdateFrequency is the frequency that kubelet computes node
	// status. If node lease feature is not enabled, it is also the frequency that
	// kubelet posts node status to master. In that case, be cautious when
	// changing the constant, it must work with nodeMonitorGracePeriod in nodecontroller.
	NodeStatusUpdateFrequency metav1.Duration
	// nodeStatusReportFrequency is the frequency that kubelet posts node
	// status to master if node status does not change. Kubelet will ignore this
	// frequency and post node status immediately if any change is detected. It is
	// only used when node lease feature is enabled.
	NodeStatusReportFrequency metav1.Duration
	// nodeLeaseDurationSeconds is the duration the Kubelet will set on its corresponding Lease.
	NodeLeaseDurationSeconds int32
	// imageMinimumGCAge is the minimum age for an unused image before it is
	// garbage collected.
	ImageMinimumGCAge metav1.Duration
	// imageGCHighThresholdPercent is the percent of disk usage after which
	// image garbage collection is always run. The percent is calculated as
	// this field value out of 100.
	ImageGCHighThresholdPercent int32
	// imageGCLowThresholdPercent is the percent of disk usage before which
	// image garbage collection is never run. Lowest disk usage to garbage
	// collect to. The percent is calculated as this field value out of 100.
	ImageGCLowThresholdPercent int32
	// How frequently to calculate and cache volume disk usage for all pods
	VolumeStatsAggPeriod metav1.Duration
	// KubeletCgroups is the absolute name of cgroups to isolate the kubelet in
	KubeletCgroups string
	// SystemCgroups is absolute name of cgroups in which to place
	// all non-kernel processes that are not already in a container. Empty
	// for no container. Rolling back the flag requires a reboot.
	SystemCgroups string
	// CgroupRoot is the root cgroup to use for pods.
	// If CgroupsPerQOS is enabled, this is the root of the QoS cgroup hierarchy.
	CgroupRoot string
	// Enable QoS based Cgroup hierarchy: top level cgroups for QoS Classes
	// And all Burstable and BestEffort pods are brought up under their
	// specific top level QoS cgroup.
	CgroupsPerQOS bool
	// driver that the kubelet uses to manipulate cgroups on the host (cgroupfs or systemd)
	CgroupDriver string
	// CPUManagerPolicy is the name of the policy to use.
	// Requires the CPUManager feature gate to be enabled.
	CPUManagerPolicy string
	// CPUManagerPolicyOptions is a set of key=value which 	allows to set extra options
	// to fine tune the behaviour of the cpu manager policies.
	// Requires  both the "CPUManager" and "CPUManagerPolicyOptions" feature gates to be enabled.
	CPUManagerPolicyOptions map[string]string
	// CPU Manager reconciliation period.
	// Requires the CPUManager feature gate to be enabled.
	CPUManagerReconcilePeriod metav1.Duration
	// MemoryManagerPolicy is the name of the policy to use.
	// Requires the MemoryManager feature gate to be enabled.
	MemoryManagerPolicy string
	// TopologyManagerPolicy is the name of the policy to use.
	// Policies other than "none" require the TopologyManager feature gate to be enabled.
	TopologyManagerPolicy string
	// TopologyManagerScope represents the scope of topology hint generation
	// that topology manager requests and hint providers generate.
	// "pod" scope requires the TopologyManager feature gate to be enabled.
	// Default: "container"
	// +optional
	TopologyManagerScope string
	// TopologyManagerPolicyOptions is a set of key=value which allows to set extra options
	// to fine tune the behaviour of the topology manager policies.
	// Requires  both the "TopologyManager" and "TopologyManagerPolicyOptions" feature gates to be enabled.
	TopologyManagerPolicyOptions map[string]string
	// Map of QoS resource reservation percentages (memory only for now).
	// Requires the QOSReserved feature gate to be enabled.
	QOSReserved map[string]string
	// runtimeRequestTimeout is the timeout for all runtime requests except long running
	// requests - pull, logs, exec and attach.
	RuntimeRequestTimeout metav1.Duration
	// hairpinMode specifies how the Kubelet should configure the container
	// bridge for hairpin packets.
	// Setting this flag allows endpoints in a Service to loadbalance back to
	// themselves if they should try to access their own Service. Values:
	//   "promiscuous-bridge": make the container bridge promiscuous.
	//   "hairpin-veth":       set the hairpin flag on container veth interfaces.
	//   "none":               do nothing.
	// Generally, one must set --hairpin-mode=hairpin-veth to achieve hairpin NAT,
	// because promiscuous-bridge assumes the existence of a container bridge named cbr0.
	HairpinMode string
	// maxPods is the number of pods that can run on this Kubelet.
	MaxPods int32
	// The CIDR to use for pod IP addresses, only used in standalone mode.
	// In cluster mode, this is obtained from the master.
	PodCIDR string
	// The maximum number of processes per pod.  If -1, the kubelet defaults to the node allocatable pid capacity.
	PodPidsLimit int64
	// ResolverConfig is the resolver configuration file used as the basis
	// for the container DNS resolution configuration.
	ResolverConfig string
	// RunOnce causes the Kubelet to check the API server once for pods,
	// run those in addition to the pods specified by static pod files, and exit.
	RunOnce bool
	// cpuCFSQuota enables CPU CFS quota enforcement for containers that
	// specify CPU limits
	CPUCFSQuota bool
	// CPUCFSQuotaPeriod sets the CPU CFS quota period value, cpu.cfs_period_us, defaults to 100ms
	CPUCFSQuotaPeriod metav1.Duration
	// maxOpenFiles is Number of files that can be opened by Kubelet process.
	MaxOpenFiles int64
	// nodeStatusMaxImages caps the number of images reported in Node.Status.Images.
	NodeStatusMaxImages int32
	// contentType is contentType of requests sent to apiserver.
	ContentType string
	// kubeAPIQPS is the QPS to use while talking with kubernetes apiserver
	KubeAPIQPS int32
	// kubeAPIBurst is the burst to allow while talking with kubernetes
	// apiserver
	KubeAPIBurst int32
	// serializeImagePulls when enabled, tells the Kubelet to pull images one at a time.
	SerializeImagePulls bool
	// Map of signal names to quantities that defines hard eviction thresholds. For example: {"memory.available": "300Mi"}.
	// Some default signals are Linux only: nodefs.inodesFree
	EvictionHard map[string]string
	// Map of signal names to quantities that defines soft eviction thresholds.  For example: {"memory.available": "300Mi"}.
	EvictionSoft map[string]string
	// Map of signal names to quantities that defines grace periods for each soft eviction signal. For example: {"memory.available": "30s"}.
	EvictionSoftGracePeriod map[string]string
	// Duration for which the kubelet has to wait before transitioning out of an eviction pressure condition.
	EvictionPressureTransitionPeriod metav1.Duration
	// Maximum allowed grace period (in seconds) to use when terminating pods in response to a soft eviction threshold being met.
	EvictionMaxPodGracePeriod int32
	// Map of signal names to quantities that defines minimum reclaims, which describe the minimum
	// amount of a given resource the kubelet will reclaim when performing a pod eviction while
	// that resource is under pressure. For example: {"imagefs.available": "2Gi"}
	EvictionMinimumReclaim map[string]string
	// podsPerCore is the maximum number of pods per core. Cannot exceed MaxPods.
	// If 0, this field is ignored.
	PodsPerCore int32
	// enableControllerAttachDetach enables the Attach/Detach controller to
	// manage attachment/detachment of volumes scheduled to this node, and
	// disables kubelet from executing any attach/detach operations
	EnableControllerAttachDetach bool
	// protectKernelDefaults, if true, causes the Kubelet to error if kernel
	// flags are not as it expects. Otherwise the Kubelet will attempt to modify
	// kernel flags to match its expectation.
	ProtectKernelDefaults bool
	// If true, Kubelet ensures a set of iptables rules are present on host.
	// These rules will serve as utility for various components, e.g. kube-proxy.
	// The rules will be created based on IPTablesMasqueradeBit and IPTablesDropBit.
	MakeIPTablesUtilChains bool
	// iptablesMasqueradeBit is the bit of the iptables fwmark space to mark for SNAT
	// Values must be within the range [0, 31]. Must be different from other mark bits.
	// Warning: Please match the value of the corresponding parameter in kube-proxy.
	// TODO: clean up IPTablesMasqueradeBit in kube-proxy
	IPTablesMasqueradeBit int32
	// iptablesDropBit is the bit of the iptables fwmark space to mark for dropping packets.
	// Values must be within the range [0, 31]. Must be different from other mark bits.
	IPTablesDropBit int32
	// featureGates is a map of feature names to bools that enable or disable alpha/experimental
	// features. This field modifies piecemeal the built-in default values from
	// "k8s.io/kubernetes/pkg/features/kube_features.go".
	FeatureGates map[string]bool
	FailSwapOn   bool // 如果节点上启用了SWAP空间，则使Kubelet无法启动。
	// memorySwap configures swap memory available to container workloads.
	// +featureGate=NodeSwap
	// +optional
	MemorySwap MemorySwapConfiguration
	// A quantity defines the maximum size of the container log file before it is rotated. For example: "5Mi" or "256Ki".
	ContainerLogMaxSize string
	// Maximum number of container log files that can be present for a container.
	ContainerLogMaxFiles int32
	// ConfigMapAndSecretChangeDetectionStrategy is a mode in which config map and secret managers are running.
	ConfigMapAndSecretChangeDetectionStrategy ResourceChangeDetectionStrategy
	// A comma separated allowlist of unsafe sysctls or sysctl patterns (ending in `*`).
	// Unsafe sysctl groups are `kernel.shm*`, `kernel.msg*`, `kernel.sem`, `fs.mqueue.*`, and `net.*`.
	// These sysctls are namespaced but not allowed by default.
	// For example: "`kernel.msg*,net.ipv4.route.min_pmtu`"
	// +optional
	AllowedUnsafeSysctls []string
	// kernelMemcgNotification if enabled, the kubelet will integrate with the kernel memcg
	// notification to determine if memory eviction thresholds are crossed rather than polling.
	KernelMemcgNotification bool

	/* the following fields are meant for Node Allocatable */

	// A set of ResourceName=ResourceQuantity (e.g. cpu=200m,memory=150G,ephemeral-storage=1G,pid=100) pairs
	// that describe resources reserved for non-kubernetes components.
	// Currently only cpu, memory and local ephemeral storage for root file system are supported.
	// See http://kubernetes.io/docs/user-guide/compute-resources for more detail.
	SystemReserved map[string]string
	// A set of ResourceName=ResourceQuantity (e.g. cpu=200m,memory=150G,ephemeral-storage=1G,pid=100) pairs
	// that describe resources reserved for kubernetes system components.
	// Currently only cpu, memory and local ephemeral storage for root file system are supported.
	// See http://kubernetes.io/docs/user-guide/compute-resources for more detail.
	KubeReserved map[string]string
	// This flag helps kubelet identify absolute name of top level cgroup used to enforce `SystemReserved` compute resource reservation for OS system daemons.
	// Refer to [Node Allocatable](https://git.k8s.io/community/contributors/design-proposals/node/node-allocatable.md) doc for more information.
	SystemReservedCgroup string
	// This flag helps kubelet identify absolute name of top level cgroup used to enforce `KubeReserved` compute resource reservation for Kubernetes node system daemons.
	// Refer to [Node Allocatable](https://git.k8s.io/community/contributors/design-proposals/node/node-allocatable.md) doc for more information.
	KubeReservedCgroup string
	// This flag specifies the various Node Allocatable enforcements that Kubelet needs to perform.
	// This flag accepts a list of options. Acceptable options are `pods`, `system-reserved` & `kube-reserved`.
	// Refer to [Node Allocatable](https://github.com/kubernetes/design-proposals-archive/blob/main/node/node-allocatable.md) doc for more information.
	EnforceNodeAllocatable []string
	// This option specifies the cpu list reserved for the host level system threads and kubernetes related threads.
	// This provide a "static" CPU list rather than the "dynamic" list by system-reserved and kube-reserved.
	// This option overwrites CPUs provided by system-reserved and kube-reserved.
	ReservedSystemCPUs string
	// The previous version for which you want to show hidden metrics.
	// Only the previous minor version is meaningful, other values will not be allowed.
	// The format is <major>.<minor>, e.g.: '1.16'.
	// The purpose of this format is make sure you have the opportunity to notice if the next release hides additional metrics,
	// rather than being surprised when they are permanently removed in the release after that.
	ShowHiddenMetricsForVersion string
	// Logging specifies the options of logging.
	// Refer [Logs Options](https://github.com/kubernetes/component-base/blob/master/logs/options.go) for more information.
	Logging logsapi.LoggingConfiguration
	// EnableSystemLogHandler enables /logs handler.
	EnableSystemLogHandler bool
	// ShutdownGracePeriod specifies the total duration that the node should delay the shutdown and total grace period for pod termination during a node shutdown.
	// Defaults to 0 seconds.
	// +featureGate=GracefulNodeShutdown
	// +optional
	ShutdownGracePeriod metav1.Duration
	// ShutdownGracePeriodCriticalPods specifies the duration used to terminate critical pods during a node shutdown. This should be less than ShutdownGracePeriod.
	// Defaults to 0 seconds.
	// For example, if ShutdownGracePeriod=30s, and ShutdownGracePeriodCriticalPods=10s, during a node shutdown the first 20 seconds would be reserved for gracefully terminating normal pods, and the last 10 seconds would be reserved for terminating critical pods.
	// +featureGate=GracefulNodeShutdown
	// +optional
	ShutdownGracePeriodCriticalPods metav1.Duration
	// ShutdownGracePeriodByPodPriority specifies the shutdown grace period for Pods based
	// on their associated priority class value.
	// When a shutdown request is received, the Kubelet will initiate shutdown on all pods
	// running on the node with a grace period that depends on the priority of the pod,
	// and then wait for all pods to exit.
	// Each entry in the array represents the graceful shutdown time a pod with a priority
	// class value that lies in the range of that value and the next higher entry in the
	// list when the node is shutting down.
	ShutdownGracePeriodByPodPriority []ShutdownGracePeriodByPodPriority
	// ReservedMemory specifies a comma-separated list of memory reservations for NUMA nodes.
	// The parameter makes sense only in the context of the memory manager feature. The memory manager will not allocate reserved memory for container workloads.
	// For example, if you have a NUMA0 with 10Gi of memory and the ReservedMemory was specified to reserve 1Gi of memory at NUMA0,
	// the memory manager will assume that only 9Gi is available for allocation.
	// You can specify a different amount of NUMA node and memory types.
	// You can omit this parameter at all, but you should be aware that the amount of reserved memory from all NUMA nodes
	// should be equal to the amount of memory specified by the node allocatable features(https://kubernetes.io/docs/tasks/administer-cluster/reserve-compute-resources/#node-allocatable).
	// If at least one node allocatable parameter has a non-zero value, you will need to specify at least one NUMA node.
	// Also, avoid specifying:
	// 1. Duplicates, the same NUMA node, and memory type, but with a different value.
	// 2. zero limits for any memory type.
	// 3. NUMAs nodes IDs that do not exist under the machine.
	// 4. memory types except for memory and hugepages-<size>
	ReservedMemory []MemoryReservation
	// EnableProfiling enables /debug/pprof handler.
	EnableProfilingHandler bool
	// EnableDebugFlagsHandler enables/debug/flags/v handler.
	EnableDebugFlagsHandler bool
	// SeccompDefault enables the use of `RuntimeDefault` as the default seccomp profile for all workloads.
	SeccompDefault bool
	// MemoryThrottlingFactor specifies the factor multiplied by the memory limit or node allocatable memory
	// when setting the cgroupv2 memory.high value to enforce MemoryQoS.
	// Decreasing this factor will set lower high limit for container cgroups and put heavier reclaim pressure
	// while increasing will put less reclaim pressure.
	// See https://kep.k8s.io/2570 for more details.
	// Default: 0.8
	// +featureGate=MemoryQoS
	// +optional
	MemoryThrottlingFactor *float64
	// registerWithTaints are an array of taints to add to a node object when
	// the kubelet registers itself. This only takes effect when registerNode
	// is true and upon the initial registration of the node.
	// +optional
	RegisterWithTaints []v1.Taint
	// registerNode enables automatic registration with the apiserver.
	// +optional
	RegisterNode bool
	// Tracing specifies the versioned configuration for OpenTelemetry tracing clients.
	// See https://kep.k8s.io/2832 for more details.
	// +featureGate=KubeletTracing
	// +optional
	Tracing *tracingapi.TracingConfiguration

	// LocalStorageCapacityIsolation enables local ephemeral storage isolation feature. The default setting is true.
	// This feature allows users to set request/limit for container's ephemeral storage and manage it in a similar way
	// as cpu and memory. It also allows setting sizeLimit for emptyDir volume, which will trigger pod eviction if disk
	// usage from the volume exceeds the limit.
	// This feature depends on the capability of detecting correct root file system disk usage. For certain systems,
	// such as kind rootless, if this capability cannot be supported, the feature LocalStorageCapacityIsolation should be
	// disabled. Once disabled, user should not set request/limit for container's ephemeral storage, or sizeLimit for emptyDir.
	// +optional
	LocalStorageCapacityIsolation bool
}

// KubeletAuthorizationMode denotes the authorization mode for the kubelet
type KubeletAuthorizationMode string

const (
	KubeletAuthorizationModeAlwaysAllow KubeletAuthorizationMode = "AlwaysAllow"
	KubeletAuthorizationModeWebhook     KubeletAuthorizationMode = "Webhook"
)

// KubeletAuthorization holds the state related to the authorization in the kublet.
type KubeletAuthorization struct {
	// Kubelet服务器的授权模式。有效选项为AlwaysAllow或Webhook。Webhook模式使用SubjectAccessReview API来确定授权。
	Mode KubeletAuthorizationMode

	// webhook contains settings related to Webhook authorization.
	Webhook KubeletWebhookAuthorization
}

// KubeletWebhookAuthorization holds the state related to the Webhook
// Authorization in the Kubelet.
type KubeletWebhookAuthorization struct {
	CacheAuthorizedTTL   metav1.Duration // 缓存来自Webhook授权程序的“已授权”响应的持续时间。
	CacheUnauthorizedTTL metav1.Duration // 缓存来自Webhook授权程序的“未授权”响应的持续时间。
}

// KubeletAuthentication holds the Kubetlet Authentication setttings.
type KubeletAuthentication struct {
	X509 KubeletX509Authentication // 包含与x509客户端证书身份验证相关的设置
	// webhook contains settings related to webhook bearer token authentication
	Webhook   KubeletWebhookAuthentication
	Anonymous KubeletAnonymousAuthentication // 包含与匿名身份验证相关的设置
}

// KubeletX509Authentication contains settings related to x509 client certificate authentication
type KubeletX509Authentication struct {
	// clientCAFile是一个PEM编码的证书包的路径。
	// 如果设置，通过由client-ca-file中的任何一个机构签名的客户端证书呈现的任何请求都将使用与客户端证书的CommonName相对应的身份进行身份验证。
	ClientCAFile string
}

// KubeletWebhookAuthentication contains settings related to webhook authentication
type KubeletWebhookAuthentication struct {
	Enabled  bool            // 使用 TokenReview API来确定承载令牌的身份验证。
	CacheTTL metav1.Duration // 缓存来自Webhook令牌验证器的响应的持续时间。
}

// KubeletAnonymousAuthentication enables anonymous requests to the kubelet server.
type KubeletAnonymousAuthentication struct {
	// 启用对Kubelet服务器的匿名请求。未被其他身份验证方法拒绝的请求将被视为匿名请求。匿名请求的用户名为system:anonymous，组名为system:unauthenticated。
	Enabled bool
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SerializedNodeConfigSource allows us to serialize NodeConfigSource
// This type is used internally by the Kubelet for tracking checkpointed dynamic configs.
// It exists in the kubeletconfig API group because it is classified as a versioned input to the Kubelet.
type SerializedNodeConfigSource struct {
	metav1.TypeMeta
	// Source is the source that we are serializing
	// +optional
	Source v1.NodeConfigSource
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CredentialProviderConfig is the configuration containing information about
// each exec credential provider. Kubelet reads this configuration from disk and enables
// each provider as specified by the CredentialProvider type.
type CredentialProviderConfig struct {
	metav1.TypeMeta

	// providers is a list of credential provider plugins that will be enabled by the kubelet.
	// Multiple providers may match against a single image, in which case credentials
	// from all providers will be returned to the kubelet. If multiple providers are called
	// for a single image, the results are combined. If providers return overlapping
	// auth keys, the value from the provider earlier in this list is used.
	Providers []CredentialProvider
}

// CredentialProvider represents an exec plugin to be invoked by the kubelet. The plugin is only
// invoked when an image being pulled matches the images handled by the plugin (see matchImages).
type CredentialProvider struct {
	// name is the required name of the credential provider. It must match the name of the
	// provider executable as seen by the kubelet. The executable must be in the kubelet's
	// bin directory (set by the --credential-provider-bin-dir flag).
	Name string

	// matchImages is a required list of strings used to match against images in order to
	// determine if this provider should be invoked. If one of the strings matches the
	// requested image from the kubelet, the plugin will be invoked and given a chance
	// to provide credentials. Images are expected to contain the registry domain
	// and URL path.
	//
	// Each entry in matchImages is a pattern which can optionally contain a port and a path.
	// Globs can be used in the domain, but not in the port or the path. Globs are supported
	// as subdomains like `*.k8s.io` or `k8s.*.io`, and top-level-domains such as `k8s.*`.
	// Matching partial subdomains like `app*.k8s.io` is also supported. Each glob can only match
	// a single subdomain segment, so `*.io` does not match *.k8s.io.
	//
	// A match exists between an image and a matchImage when all of the below are true:
	// - Both contain the same number of domain parts and each part matches.
	// - The URL path of an imageMatch must be a prefix of the target image URL path.
	// - If the imageMatch contains a port, then the port must match in the image as well.
	//
	// Example values of matchImages:
	//   - `123456789.dkr.ecr.us-east-1.amazonaws.com`
	//   - `*.azurecr.io`
	//   - `gcr.io`
	//   - `*.*.registry.io`
	//   - `registry.io:8080/path`
	MatchImages []string

	// defaultCacheDuration is the default duration the plugin will cache credentials in-memory
	// if a cache duration is not provided in the plugin response. This field is required.
	DefaultCacheDuration *metav1.Duration

	// Required input version of the exec CredentialProviderRequest. The returned CredentialProviderResponse
	// MUST use the same encoding version as the input. Current supported values are:
	// - credentialprovider.kubelet.k8s.io/v1alpha1
	// - credentialprovider.kubelet.k8s.io/v1beta1
	// - credentialprovider.kubelet.k8s.io/v1
	APIVersion string

	// Arguments to pass to the command when executing it.
	// +optional
	Args []string

	// Env defines additional environment variables to expose to the process. These
	// are unioned with the host's environment, as well as variables client-go uses
	// to pass argument to the plugin.
	// +optional
	Env []ExecEnvVar
}

// ExecEnvVar is used for setting environment variables when executing an exec-based
// credential plugin.
type ExecEnvVar struct {
	Name  string
	Value string
}

// MemoryReservation specifies the memory reservation of different types for each NUMA node
type MemoryReservation struct {
	NumaNode int32
	Limits   v1.ResourceList
}

// ShutdownGracePeriodByPodPriority specifies the shutdown grace period for Pods based on their associated priority class value
type ShutdownGracePeriodByPodPriority struct {
	// priority is the priority value associated with the shutdown grace period
	Priority int32
	// shutdownGracePeriodSeconds is the shutdown grace period in seconds
	ShutdownGracePeriodSeconds int64
}

type MemorySwapConfiguration struct {
	// swapBehavior configures swap memory available to container workloads. May be one of
	// "", "LimitedSwap": workload combined memory and swap usage cannot exceed pod memory limit
	// "UnlimitedSwap": workloads can use unlimited swap, up to the allocatable limit.
	// +featureGate=NodeSwap
	// +optional
	SwapBehavior string
}
