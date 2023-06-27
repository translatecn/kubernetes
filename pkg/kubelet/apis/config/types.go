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

//
//
//   看  staging/src/k8s.io/kubelet/config/v1beta1/types.go
//

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

type KubeletConfiguration struct { // --config
	metav1.TypeMeta

	EnableServer                              bool
	StaticPodPath                             string
	SyncFrequency                             metav1.Duration
	FileCheckFrequency                        metav1.Duration
	HTTPCheckFrequency                        metav1.Duration
	StaticPodURL                              string
	StaticPodURLHeader                        map[string][]string `datapolicy:"token"`
	Address                                   string
	Port                                      int32
	ReadOnlyPort                              int32
	VolumePluginDir                           string
	ProviderID                                string
	TLSCertFile                               string
	TLSPrivateKeyFile                         string
	TLSCipherSuites                           []string
	TLSMinVersion                             string
	RotateCertificates                        bool
	ServerTLSBootstrap                        bool
	Authentication                            KubeletAuthentication
	Authorization                             KubeletAuthorization
	RegistryPullQPS                           int32
	RegistryBurst                             int32
	EventRecordQPS                            int32
	EventBurst                                int32
	EnableDebuggingHandlers                   bool
	EnableContentionProfiling                 bool
	HealthzPort                               int32
	HealthzBindAddress                        string
	OOMScoreAdj                               int32
	ClusterDomain                             string
	ClusterDNS                                []string
	StreamingConnectionIdleTimeout            metav1.Duration
	NodeStatusUpdateFrequency                 metav1.Duration
	NodeStatusReportFrequency                 metav1.Duration
	NodeLeaseDurationSeconds                  int32
	ImageMinimumGCAge                         metav1.Duration
	ImageGCHighThresholdPercent               int32
	ImageGCLowThresholdPercent                int32
	VolumeStatsAggPeriod                      metav1.Duration
	KubeletCgroups                            string
	SystemCgroups                             string
	CgroupRoot                                string
	CgroupsPerQOS                             bool
	CgroupDriver                              string
	CPUManagerPolicy                          string
	CPUManagerPolicyOptions                   map[string]string
	CPUManagerReconcilePeriod                 metav1.Duration
	MemoryManagerPolicy                       string
	TopologyManagerPolicy                     string
	TopologyManagerScope                      string
	TopologyManagerPolicyOptions              map[string]string
	QOSReserved                               map[string]string
	RuntimeRequestTimeout                     metav1.Duration
	HairpinMode                               string
	MaxPods                                   int32
	PodCIDR                                   string
	PodPidsLimit                              int64
	ResolverConfig                            string
	RunOnce                                   bool
	CPUCFSQuota                               bool
	CPUCFSQuotaPeriod                         metav1.Duration
	MaxOpenFiles                              int64
	NodeStatusMaxImages                       int32
	ContentType                               string
	KubeAPIQPS                                int32
	KubeAPIBurst                              int32
	SerializeImagePulls                       bool
	EvictionHard                              map[string]string
	EvictionSoft                              map[string]string
	EvictionSoftGracePeriod                   map[string]string
	EvictionPressureTransitionPeriod          metav1.Duration
	EvictionMaxPodGracePeriod                 int32
	EvictionMinimumReclaim                    map[string]string
	PodsPerCore                               int32
	EnableControllerAttachDetach              bool
	ProtectKernelDefaults                     bool
	MakeIPTablesUtilChains                    bool
	IPTablesMasqueradeBit                     int32
	IPTablesDropBit                           int32
	FeatureGates                              map[string]bool
	FailSwapOn                                bool
	MemorySwap                                MemorySwapConfiguration
	ContainerLogMaxSize                       string
	ContainerLogMaxFiles                      int32
	ConfigMapAndSecretChangeDetectionStrategy ResourceChangeDetectionStrategy
	AllowedUnsafeSysctls                      []string
	KernelMemcgNotification                   bool
	SystemReserved                            map[string]string
	KubeReserved                              map[string]string
	SystemReservedCgroup                      string
	KubeReservedCgroup                        string
	EnforceNodeAllocatable                    []string
	ReservedSystemCPUs                        string
	ShowHiddenMetricsForVersion               string
	Logging                                   logsapi.LoggingConfiguration
	EnableSystemLogHandler                    bool
	ShutdownGracePeriod                       metav1.Duration
	// +featureGate=GracefulNodeShutdown
	// +optional
	ShutdownGracePeriodCriticalPods  metav1.Duration
	ShutdownGracePeriodByPodPriority []ShutdownGracePeriodByPodPriority
	ReservedMemory                   []MemoryReservation
	EnableProfilingHandler           bool
	EnableDebugFlagsHandler          bool
	SeccompDefault                   bool
	MemoryThrottlingFactor           *float64
	RegisterWithTaints               []v1.Taint
	RegisterNode                     bool
	Tracing                          *tracingapi.TracingConfiguration

	// LocalStorageCapacityIsolation 启用本地临时存储隔离功能.默认设置为true.此功能允许用户为容器的临时存储设置request/limit,并以类似于CPU和内存的方式进行管理.它还允许为emptyDir卷设置sizeLimit,如果来自卷的磁盘使用超过限制,则会触发Pod驱逐.
	//
	// 此功能取决于检测正确的根文件系统磁盘使用情况的能力.对于某些系统,例如kind rootless,如果无法支持此功能,则应禁用LocalStorageCapacityIsolation.一旦禁用,用户不应为容器的临时存储设置请求/限制,或为emptyDir设置sizeLimit.
	// 如果开启了LocalStorageCapacityIsolation特性就通过 cadvisor接口获取 rootfsinfo

	// - 然后将类型为ephemeral-storage的存储的容量设置为rootfs获取到的
	// +optionalLocalStorageCapacityIsolation
	LocalStorageCapacityIsolation bool
}

// KubeletAuthorizationMode denotes the authorization mode for the kubelet
type KubeletAuthorizationMode string

const (
	// KubeletAuthorizationModeAlwaysAllow authorizes all authenticated requests
	KubeletAuthorizationModeAlwaysAllow KubeletAuthorizationMode = "AlwaysAllow"
	// KubeletAuthorizationModeWebhook uses the SubjectAccessReview API to determine authorization
	KubeletAuthorizationModeWebhook KubeletAuthorizationMode = "Webhook"
)

// KubeletAuthorization holds the state related to the authorization in the kublet.
type KubeletAuthorization struct {
	// mode is the authorization mode to apply to requests to the kubelet server.
	// Valid values are AlwaysAllow and Webhook.
	// Webhook mode uses the SubjectAccessReview API to determine authorization.
	Mode KubeletAuthorizationMode

	// webhook contains settings related to Webhook authorization.
	Webhook KubeletWebhookAuthorization
}

// KubeletWebhookAuthorization holds the state related to the Webhook
// Authorization in the Kubelet.
type KubeletWebhookAuthorization struct {
	// cacheAuthorizedTTL is the duration to cache 'authorized' responses from the webhook authorizer.
	CacheAuthorizedTTL metav1.Duration
	// cacheUnauthorizedTTL is the duration to cache 'unauthorized' responses from the webhook authorizer.
	CacheUnauthorizedTTL metav1.Duration
}

// KubeletAuthentication holds the Kubetlet Authentication setttings.
type KubeletAuthentication struct {
	// x509 contains settings related to x509 client certificate authentication
	X509 KubeletX509Authentication
	// webhook contains settings related to webhook bearer token authentication
	Webhook KubeletWebhookAuthentication
	// anonymous contains settings related to anonymous authentication
	Anonymous KubeletAnonymousAuthentication
}

// KubeletX509Authentication contains settings related to x509 client certificate authentication
type KubeletX509Authentication struct {
	// clientCAFile is the path to a PEM-encoded certificate bundle. If set, any request presenting a client certificate
	// signed by one of the authorities in the bundle is authenticated with a username corresponding to the CommonName,
	// and groups corresponding to the Organization in the client certificate.
	ClientCAFile string
}

// KubeletWebhookAuthentication contains settings related to webhook authentication
type KubeletWebhookAuthentication struct {
	// enabled allows bearer token authentication backed by the tokenreviews.authentication.k8s.io API
	Enabled bool
	// cacheTTL enables caching of authentication results
	CacheTTL metav1.Duration
}

// KubeletAnonymousAuthentication enables anonymous requests to the kubelet server.
type KubeletAnonymousAuthentication struct {
	// enabled allows anonymous requests to the kubelet server.
	// Requests that are not rejected by another authentication method are treated as anonymous requests.
	// Anonymous requests have a username of system:anonymous, and a group name of system:unauthenticated.
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
	Limits   v1.ResourceMap
}

// ShutdownGracePeriodByPodPriority pod优雅关闭的配置
type ShutdownGracePeriodByPodPriority struct {
	Priority                   int32 // 优先级
	ShutdownGracePeriodSeconds int64 // 优雅关闭等待的时间
}

type MemorySwapConfiguration struct {
	// swapBehavior configures swap memory available to container workloads. May be one of
	// "", "LimitedSwap": workload combined memory and swap usage cannot exceed pod memory limit
	// "UnlimitedSwap": workloads can use unlimited swap, up to the allocatable limit.
	// +featureGate=NodeSwap
	// +optional
	SwapBehavior string
}
