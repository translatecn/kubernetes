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

package server

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"net"
	"net/http"
	"os"
	goruntime "runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/google/uuid"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	utilwaitgroup "k8s.io/apimachinery/pkg/util/waitgroup"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/audit"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/authenticatorfactory"
	authenticatorunion "k8s.io/apiserver/pkg/authentication/request/union"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/discovery"
	discoveryendpoint "k8s.io/apiserver/pkg/endpoints/discovery/aggregated"
	"k8s.io/apiserver/pkg/endpoints/filterlatency"
	genericapifilters "k8s.io/apiserver/pkg/endpoints/filters"
	apiopenapi "k8s.io/apiserver/pkg/endpoints/openapi"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	genericfeatures "k8s.io/apiserver/pkg/features"
	genericregistry "k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/apiserver/pkg/server/egressselector"
	genericfilters "k8s.io/apiserver/pkg/server/filters"
	"k8s.io/apiserver/pkg/server/healthz"
	"k8s.io/apiserver/pkg/server/routes"
	serverstore "k8s.io/apiserver/pkg/server/storage"
	"k8s.io/apiserver/pkg/storageversion"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	utilflowcontrol "k8s.io/apiserver/pkg/util/flowcontrol"
	flowcontrolrequest "k8s.io/apiserver/pkg/util/flowcontrol/request"
	"k8s.io/client-go/informers"
	restclient "k8s.io/client-go/rest"
	"k8s.io/component-base/logs"
	"k8s.io/component-base/metrics/features"
	"k8s.io/component-base/metrics/prometheus/slis"
	"k8s.io/component-base/tracing"
	"k8s.io/klog/v2"
	openapicommon "k8s.io/kube-openapi/pkg/common"
	"k8s.io/kube-openapi/pkg/validation/spec"
	"k8s.io/utils/clock"
	utilsnet "k8s.io/utils/net"

	// install apis
	_ "k8s.io/apiserver/pkg/apis/apiserver/install"
)

const (
	// DefaultLegacyAPIPrefix 是遗留API组所在的位置。
	DefaultLegacyAPIPrefix = "/api"

	// APIGroupPrefix 是非遗留API组所在的位置。
	APIGroupPrefix = "/apis"
)

// Config is a structure used to configure a GenericAPIServer.
// Its members are sorted roughly in order of importance for composers.
type Config struct {
	// SecureServing is required to serve https
	SecureServing *SecureServingInfo

	// Authentication is the configuration for authentication
	Authentication AuthenticationInfo

	// Authorization is the configuration for authorization
	Authorization AuthorizationInfo

	LoopbackClientConfig *restclient.Config             // 是一个与API服务器的特权环回连接的配置。这对于GenericAPIServer上的PostStartHooks的正常运行是必需的。  s.SecureServing.ApplyTo(&gener
	EgressSelector       *egressselector.EgressSelector // EgressSelector为拨出站连接提供查找机制。它基于启动时读取的EgressSelectorConfiguration。

	// 要获取适用于给定命名空间中给定用户的规则列表，需要RuleResolver。
	RuleResolver          authorizer.RuleResolver
	AdmissionControl      admission.Interface // 对给定的请求(包括内容)执行深度检查，以设置值并确定是否允许
	CorsAllowedOriginList []string            // CORS允许的源列表
	HSTSDirectives        []string            // https://zhuanlan.zhihu.com/p/130946490
	// FlowControl, if not nil, gives priority and fairness to request handling
	FlowControl utilflowcontrol.Interface

	EnableIndex     bool
	EnableProfiling bool
	EnableDiscovery bool

	EnableContentionProfiling bool // todo 需要启用通用概要分析
	EnableMetrics             bool

	DisabledPostStartHooks sets.String
	PostStartHooks         map[string]PostStartHookConfigEntry

	// Version will enable the /version endpoint if non-nil
	Version *version.Info

	AuditBackend             audit.Backend             // 审计日志后端
	AuditPolicyRuleEvaluator audit.PolicyRuleEvaluator // 决定是否以及如何审计请求的日志。
	// ExternalAddress is the host name to use for external (public internet) facing URLs (e.g. Swagger)
	// Will default to a value based on secure serving info and available ipv4 IPs.
	ExternalAddress string

	TracerProvider tracing.TracerProvider // 可以提供跟踪程序,用于记录用于分布式跟踪的范围.

	//===========================================================================
	// 您可能不关心更改的字段。
	//===========================================================================

	BuildHandlerChainFunc func(apiHandler http.Handler, c *Config) (secure http.Handler) // 允许您通过装饰apiHandler构建自定义处理程序链。
	HandlerChainWaitGroup *utilwaitgroup.SafeWaitGroup                                   // 在服务器关闭后，允许您等待所有链处理程序退出。
	// DiscoveryAddresses is used to build the IPs pass to discovery. If nil, the ExternalAddress is
	// always reported
	DiscoveryAddresses discovery.Addresses
	// The default set of healthz checks. There might be more added via AddHealthChecks dynamically.
	HealthzChecks []healthz.HealthChecker
	// The default set of livez checks. There might be more added via AddHealthChecks dynamically.
	LivezChecks []healthz.HealthChecker
	// The default set of readyz-only checks. There might be more added via AddReadyzChecks dynamically.
	ReadyzChecks           []healthz.HealthChecker
	LegacyAPIGroupPrefixes sets.String                    // 用于设置URL解析以进行授权，并验证对InstallLegacyAPIGroup的请求。内置资源的前缀
	RequestInfoResolver    apirequest.RequestInfoResolver // 根据请求URL分配属性（由审核和授权使用）。
	// Serializer is required and provides the interface for serializing and converting objects to and from the wire
	// The default (api.Codecs) usually works fine.
	Serializer runtime.NegotiatedSerializer
	// OpenAPIConfig will be used in generating OpenAPI spec. This is nil by default. Use DefaultOpenAPIConfig for "working" defaults.
	OpenAPIConfig *openapicommon.Config
	// OpenAPIV3Config will be used in generating OpenAPI V3 spec. This is nil by default. Use DefaultOpenAPIV3Config for "working" defaults.
	OpenAPIV3Config *openapicommon.Config
	// SkipOpenAPIInstallation avoids installing the OpenAPI handler if set to true.
	SkipOpenAPIInstallation bool

	RESTOptionsGetter genericregistry.RESTOptionsGetter // 用来通过通用注册表构建RESTStorage类型。
	RequestTimeout    time.Duration                     // 所有请求都将在此持续时间后超时,默认60s

	// If specified, long running requests such as watch will be allocated a random timeout between this value, and
	// twice this value.  Note that it is up to the request handlers to ignore or honor this timeout. In seconds.
	MinRequestTimeout int

	// This represents the maximum amount of time it should take for apiserver to complete its startup
	// sequence and become healthy. From apiserver's start time to when this amount of time has
	// elapsed, /livez will assume that unfinished post-start hooks will complete successfully and
	// therefore return true.
	LivezGracePeriod time.Duration
	// ShutdownDelayDuration allows to block shutdown for some time, e.g. until endpoints pointing to this API server
	// have converged on all node. During this time, the API server keeps serving, /healthz will return 200,
	// but /readyz will return failure.
	ShutdownDelayDuration time.Duration

	// The limit on the total size increase all "copy" operations in a json
	// patch may cause.
	// This affects all places that applies json patch in the binary.
	JSONPatchMaxCopyBytes int64
	// The limit on the request size that would be accepted and decoded in a write request
	// 0 means no limit.
	MaxRequestBodyBytes         int64
	MaxRequestsInFlight         int                                // 运行中的请求的最大数目.仅适用于非突变请求.400
	MaxMutatingRequestsInFlight int                                // 运行中的请求的最大数目.适用于突变请求. 200
	LongRunningFunc             apirequest.LongRunningRequestCheck // 对于长时间运行的HTTP请求的路径为真。

	// GoawayChance是向HTTP/2客户端发送GOAWAY的概率。
	// 当客户端收到GOAWAY时，正在进行的请求不会受到影响，并且新请求将使用新的TCP连接触发重新平衡到负载均衡后面的另一个服务器。
	// 默认为0，表示从不发送GOAWAY。最大值为0.02，以防止破坏apiserver。
	GoawayChance float64

	MergedResourceConfig *serverstore.ResourceConfig // 表示哪个groupVersion启用,其资源启用/禁用.

	// lifecycleSignals provides access to the various signals
	// that happen during lifecycle of the apiserver.
	// it's intentionally marked private as it should never be overridden.
	lifecycleSignals lifecycleSignals

	// StorageObjectCountTracker is used to keep track of the total number of objects
	// in the storage per resource, so we can estimate width of incoming requests.
	StorageObjectCountTracker flowcontrolrequest.StorageObjectCountTracker

	// 在apiserver优雅终止期间指示何时启动HTTP服务器的关闭。如果为true，则等待正在进行中的非长时间运行请求被处理完毕，然后启动HTTP服务器的关闭。
	// 如果为false，则在ShutdownDelayDuration已经过时后立即启动HTTP服务器的关闭。
	// 如果启用，则在ShutdownDelayDuration过期后，任何传入的请求都将被拒绝，并带有429状态代码和'Retry-After'响应。
	ShutdownSendRetryAfter bool

	//===========================================================================
	// values below here are targets for removal
	//===========================================================================

	// PublicAddress is the IP address where members of the cluster (kubelet,
	// kube-proxy, services, etc.) can reach the GenericAPIServer.
	// If nil or 0.0.0.0, the host's default interface will be used.
	PublicAddress net.IP

	// EquivalentResourceRegistry provides information about resources equivalent to a given resource,
	// and the kind associated with a given resource. As resources are installed, they are registered here.
	EquivalentResourceRegistry runtime.EquivalentResourceRegistry

	// APIServerID is the ID of this API server
	APIServerID string

	StorageVersionManager storageversion.Manager // 保存该服务器安装的API资源

	// AggregatedDiscoveryGroupManager serves /apis in an aggregated form.
	AggregatedDiscoveryGroupManager discoveryendpoint.ResourceManager
}

type RecommendedConfig struct {
	Config
	SharedInformerFactory informers.SharedInformerFactory

	// ClientConfig holds the kubernetes client configuration.
	// This value is set by RecommendedOptions.CoreAPI.ApplyTo called by RecommendedOptions.ApplyTo.
	// By default in-cluster client config is used.
	ClientConfig *restclient.Config
}

type SecureServingInfo struct {
	Listener                     net.Listener                                    // 安全服务器是网络监听器
	Cert                         dynamiccertificates.CertKeyContentProvider      // Cert是主服务器证书，如果SNI不匹配，将使用该证书。Cert必须是非nil，并且允许在SNICerts中。
	SNICerts                     []dynamiccertificates.SNICertKeyContentProvider // 是用于SNI的TLS证书。
	ClientCA                     dynamiccertificates.CAContentProvider           // 证书包是否包含您将为传入的客户端证书识别的所有签名者
	MinTLSVersion                uint16                                          // 支持的最小TLS版本。
	CipherSuites                 []uint16                                        // 服务器允许的密码套件列表。
	HTTP2MaxStreamsPerConnection int                                             // 是API服务器对每个客户机施加的限制。值为0意味着使用golang的HTTP/2支持提供的默认值。
	DisableHTTP2                 bool                                            // 表示http2不应该被启用。
}

type AuthenticationInfo struct {
	APIAudiences  authenticator.Audiences // APIAudiences是API识别的标识符列表。这由某些身份验证器用于验证面向受众的凭据。
	Authenticator authenticator.Request   // 请求验证器
}

type AuthorizationInfo struct {
	Authorizer authorizer.Authorizer // 仅基于RequestURI确定是否允许主体发出请求。
}

func init() {
	utilruntime.Must(features.AddFeatureGates(utilfeature.DefaultMutableFeatureGate))
}

// NewConfig returns a Config struct with the default values
func NewConfig(codecs serializer.CodecFactory) *Config {
	defaultHealthChecks := []healthz.HealthChecker{healthz.PingHealthz, healthz.LogHealthz}
	var id string
	if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.APIServerIdentity) { // 在集群中为每个kube-apiserver分配一个ID
		hostname, err := os.Hostname()
		if err != nil {
			klog.Fatalf("error getting hostname for apiserver identity: %v", err)
		}

		hash := sha256.Sum256([]byte(hostname))
		id = "kube-apiserver-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hash[:16]))
	}
	lifecycleSignals := newLifecycleSignals()

	return &Config{
		Serializer:                  codecs,
		BuildHandlerChainFunc:       DefaultBuildHandlerChain,
		HandlerChainWaitGroup:       new(utilwaitgroup.SafeWaitGroup),
		LegacyAPIGroupPrefixes:      sets.NewString(DefaultLegacyAPIPrefix),
		DisabledPostStartHooks:      sets.NewString(),
		PostStartHooks:              map[string]PostStartHookConfigEntry{},
		HealthzChecks:               append([]healthz.HealthChecker{}, defaultHealthChecks...),
		ReadyzChecks:                append([]healthz.HealthChecker{}, defaultHealthChecks...),
		LivezChecks:                 append([]healthz.HealthChecker{}, defaultHealthChecks...),
		EnableIndex:                 true,
		EnableDiscovery:             true,
		EnableProfiling:             true,
		EnableMetrics:               true,
		MaxRequestsInFlight:         400,
		MaxMutatingRequestsInFlight: 200,
		RequestTimeout:              time.Duration(60) * time.Second,
		MinRequestTimeout:           1800,
		LivezGracePeriod:            time.Duration(0),
		ShutdownDelayDuration:       time.Duration(0),
		JSONPatchMaxCopyBytes:       int64(3 * 1024 * 1024), //  1.5MB是默认的客户端请求大小,以字节为单位 etcd服务器应该接受. 因为请求是json, 最终以proto 存储在etcd ,所以可以大小*2
		MaxRequestBodyBytes:         int64(3 * 1024 * 1024),
		LongRunningFunc:             genericfilters.BasicLongRunningRequestCheck(sets.NewString("watch"), sets.NewString()),
		lifecycleSignals:            lifecycleSignals,
		StorageObjectCountTracker:   flowcontrolrequest.NewStorageObjectCountTracker(), // 跟踪每个资源的对象总数
		APIServerID:                 id,
		StorageVersionManager:       storageversion.NewDefaultManager(),
		TracerProvider:              tracing.NewNoopTracerProvider(),
	}
}

// NewRecommendedConfig returns a RecommendedConfig struct with the default values
func NewRecommendedConfig(codecs serializer.CodecFactory) *RecommendedConfig {
	return &RecommendedConfig{
		Config: *NewConfig(codecs),
	}
}

// DefaultOpenAPIConfig provides the default OpenAPIConfig used to build the OpenAPI V2 spec
func DefaultOpenAPIConfig(getDefinitions openapicommon.GetOpenAPIDefinitions, defNamer *apiopenapi.DefinitionNamer) *openapicommon.Config {
	return &openapicommon.Config{
		ProtocolList:   []string{"https"},
		IgnorePrefixes: []string{},
		Info: &spec.Info{
			InfoProps: spec.InfoProps{
				Title: "Generic API Server",
			},
		},
		DefaultResponse: &spec.Response{
			ResponseProps: spec.ResponseProps{
				Description: "Default Response.",
			},
		},
		GetOperationIDAndTags: apiopenapi.GetOperationIDAndTags,
		GetDefinitionName:     defNamer.GetDefinitionName,
		GetDefinitions:        getDefinitions,
	}
}

// DefaultOpenAPIV3Config provides the default OpenAPIV3Config used to build the OpenAPI V3 spec
func DefaultOpenAPIV3Config(getDefinitions openapicommon.GetOpenAPIDefinitions, defNamer *apiopenapi.DefinitionNamer) *openapicommon.Config {
	defaultConfig := DefaultOpenAPIConfig(getDefinitions, defNamer)
	defaultConfig.Definitions = getDefinitions(func(name string) spec.Ref {
		defName, _ := defaultConfig.GetDefinitionName(name)
		return spec.MustCreateRef("#/components/schemas/" + openapicommon.EscapeJsonPointer(defName))
	})

	return defaultConfig
}

func (c *AuthenticationInfo) ApplyClientCert(clientCA dynamiccertificates.CAContentProvider, servingInfo *SecureServingInfo) error {
	if servingInfo == nil {
		return nil
	}
	if clientCA == nil {
		return nil
	}
	if servingInfo.ClientCA == nil {
		servingInfo.ClientCA = clientCA
		return nil
	}

	servingInfo.ClientCA = dynamiccertificates.NewUnionCAContentProvider(servingInfo.ClientCA, clientCA)
	return nil
}

type completedConfig struct {
	*Config

	//===========================================================================
	// values below here are filled in during completion
	//===========================================================================

	// SharedInformerFactory provides shared informers for resources
	SharedInformerFactory informers.SharedInformerFactory
}

type CompletedConfig struct {
	// Embed a private pointer that cannot be instantiated outside of this package.
	*completedConfig
}

// AddHealthChecks adds a health check to our config to be exposed by the health endpoints
// of our configured apiserver. We should prefer this to adding healthChecks directly to
// the config unless we explicitly want to add a healthcheck only to a specific health endpoint.
func (c *Config) AddHealthChecks(healthChecks ...healthz.HealthChecker) {
	c.HealthzChecks = append(c.HealthzChecks, healthChecks...)
	c.LivezChecks = append(c.LivezChecks, healthChecks...)
	c.ReadyzChecks = append(c.ReadyzChecks, healthChecks...)
}

// AddReadyzChecks adds a health check to our config to be exposed by the readyz endpoint
// of our configured apiserver.
func (c *Config) AddReadyzChecks(healthChecks ...healthz.HealthChecker) {
	c.ReadyzChecks = append(c.ReadyzChecks, healthChecks...)
}

// AddPostStartHook 允许你添加一个PostStartHook，该PostStartHook稍后将在New调用中添加到服务器本身。
func (c *Config) AddPostStartHook(name string, hook PostStartHookFunc) error {
	if len(name) == 0 {
		return fmt.Errorf("missing name")
	}
	if hook == nil {
		return fmt.Errorf("hook func may not be nil: %q", name)
	}
	if c.DisabledPostStartHooks.Has(name) {
		klog.V(1).Infof("skipping %q because it was explicitly disabled", name)
		return nil
	}

	if postStartHook, exists := c.PostStartHooks[name]; exists {
		return fmt.Errorf("无法添加%q，因为它存在: %s", name, postStartHook.originatingStack)
	}
	c.PostStartHooks[name] = PostStartHookConfigEntry{hook: hook, originatingStack: string(debug.Stack())}

	return nil
}

// AddPostStartHookOrDie allows you to add a PostStartHook, but dies on failure.
func (c *Config) AddPostStartHookOrDie(name string, hook PostStartHookFunc) {
	if err := c.AddPostStartHook(name, hook); err != nil {
		klog.Fatalf("Error registering PostStartHook %q: %v", name, err)
	}
}

func completeOpenAPI(config *openapicommon.Config, version *version.Info) {
	if config == nil {
		return
	}
	if config.SecurityDefinitions != nil {
		// Setup OpenAPI security: all APIs will have the same authentication for now.
		config.DefaultSecurity = []map[string][]string{}
		keys := []string{}
		for k := range *config.SecurityDefinitions {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			config.DefaultSecurity = append(config.DefaultSecurity, map[string][]string{k: {}})
		}
		if config.CommonResponses == nil {
			config.CommonResponses = map[int]spec.Response{}
		}
		if _, exists := config.CommonResponses[http.StatusUnauthorized]; !exists {
			config.CommonResponses[http.StatusUnauthorized] = spec.Response{
				ResponseProps: spec.ResponseProps{
					Description: "Unauthorized",
				},
			}
		}
	}
	// make sure we populate info, and info.version, if not manually set
	if config.Info == nil {
		config.Info = &spec.Info{}
	}
	if config.Info.Version == "" {
		if version != nil {
			config.Info.Version = strings.Split(version.String(), "-")[0]
		} else {
			config.Info.Version = "unversioned"
		}
	}
}

// DrainedNotify 返回genericapisserver在关闭时已经耗尽的生命周期信号。
func (c *Config) DrainedNotify() <-chan struct{} {
	return c.lifecycleSignals.InFlightRequestsDrained.Signaled()
}

// Complete fills in any fields not set that are required to have valid data and can be derived
// from other fields. If you're going to `ApplyOptions`, do that first. It's mutating the receiver.
func (c *Config) Complete(informers informers.SharedInformerFactory) CompletedConfig {
	if len(c.ExternalAddress) == 0 && c.PublicAddress != nil {
		c.ExternalAddress = c.PublicAddress.String()
	}

	// if there is no port, and we listen on one securely, use that one
	if _, _, err := net.SplitHostPort(c.ExternalAddress); err != nil {
		if c.SecureServing == nil {
			klog.Fatalf("cannot derive external address port without listening on a secure port.")
		}
		_, port, err := c.SecureServing.HostPort()
		if err != nil {
			klog.Fatalf("cannot derive external address from the secure port: %v", err)
		}
		c.ExternalAddress = net.JoinHostPort(c.ExternalAddress, strconv.Itoa(port))
	}

	completeOpenAPI(c.OpenAPIConfig, c.Version)
	completeOpenAPI(c.OpenAPIV3Config, c.Version)

	if c.DiscoveryAddresses == nil {
		c.DiscoveryAddresses = discovery.DefaultAddresses{DefaultAddress: c.ExternalAddress}
	}

	AuthorizeClientBearerToken(c.LoopbackClientConfig, &c.Authentication, &c.Authorization)

	if c.RequestInfoResolver == nil {
		c.RequestInfoResolver = NewRequestInfoResolver(c)
	}

	if c.EquivalentResourceRegistry == nil {
		if c.RESTOptionsGetter == nil {
			c.EquivalentResourceRegistry = runtime.NewEquivalentResourceRegistry()
		} else {
			c.EquivalentResourceRegistry = runtime.NewEquivalentResourceRegistryWithIdentity(func(groupResource schema.GroupResource) string {
				// use the storage prefix as the key if possible
				if opts, err := c.RESTOptionsGetter.GetRESTOptions(groupResource); err == nil {
					return opts.ResourcePrefix
				}
				// otherwise return "" to use the default key (parent GV name)
				return ""
			})
		}
	}

	return CompletedConfig{&completedConfig{c, informers}}
}

func (c *RecommendedConfig) Complete() CompletedConfig {
	return c.Config.Complete(c.SharedInformerFactory)
}

// New ✅ 基础方法
// 创建一个新服务器，该服务器在逻辑上将处理链与传递的server.name用于区分日志记录。
// CreateKubeAPIServer
func (c completedConfig) New(name string, delegationTarget DelegationTarget) (*GenericAPIServer, error) {
	if c.Serializer == nil {
		return nil, fmt.Errorf("Genericapiserver.New() called with config.Serializer == nil")
	}
	if c.LoopbackClientConfig == nil {
		return nil, fmt.Errorf("Genericapiserver.New() called with config.LoopbackClientConfig == nil")
	}
	if c.EquivalentResourceRegistry == nil {
		return nil, fmt.Errorf("Genericapiserver.New() called with config.EquivalentResourceRegistry == nil")
	}

	handlerChainBuilder := func(handler http.Handler) http.Handler { // 补充中间件
		return c.BuildHandlerChainFunc(handler, c.Config)
	}

	apiServerHandler := NewAPIServerHandler(name, c.Serializer, handlerChainBuilder, delegationTarget.UnprotectedHandler()) // 创建了一个url集合

	s := &GenericAPIServer{
		discoveryAddresses:         c.DiscoveryAddresses,
		LoopbackClientConfig:       c.LoopbackClientConfig,
		legacyAPIGroupPrefixes:     c.LegacyAPIGroupPrefixes,
		admissionControl:           c.AdmissionControl,
		Serializer:                 c.Serializer,
		AuditBackend:               c.AuditBackend,
		Authorizer:                 c.Authorization.Authorizer,
		delegationTarget:           delegationTarget,
		EquivalentResourceRegistry: c.EquivalentResourceRegistry,
		HandlerChainWaitGroup:      c.HandlerChainWaitGroup,
		Handler:                    apiServerHandler,

		listedPathProvider: apiServerHandler,

		minRequestTimeout:     time.Duration(c.MinRequestTimeout) * time.Second,
		ShutdownTimeout:       c.RequestTimeout,
		ShutdownDelayDuration: c.ShutdownDelayDuration,
		SecureServingInfo:     c.SecureServing,
		ExternalAddress:       c.ExternalAddress,

		openAPIConfig:           c.OpenAPIConfig,
		openAPIV3Config:         c.OpenAPIV3Config,
		skipOpenAPIInstallation: c.SkipOpenAPIInstallation,

		postStartHooks:         map[string]postStartHookEntry{},
		preShutdownHooks:       map[string]preShutdownHookEntry{},
		disabledPostStartHooks: c.DisabledPostStartHooks,

		healthzChecks:    c.HealthzChecks,
		livezChecks:      c.LivezChecks,
		readyzChecks:     c.ReadyzChecks,
		livezGracePeriod: c.LivezGracePeriod,

		DiscoveryGroupManager: discovery.NewRootAPIsHandler(c.DiscoveryAddresses, c.Serializer),

		maxRequestBodyBytes: c.MaxRequestBodyBytes,
		livezClock:          clock.RealClock{},

		lifecycleSignals:       c.lifecycleSignals,
		ShutdownSendRetryAfter: c.ShutdownSendRetryAfter,

		APIServerID:           c.APIServerID,
		StorageVersionManager: c.StorageVersionManager,

		Version: c.Version,

		muxAndDiscoveryCompleteSignals: map[string]<-chan struct{}{},
	}

	if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.AggregatedDiscoveryEndpoint) {
		manager := c.AggregatedDiscoveryGroupManager
		if manager == nil {
			manager = discoveryendpoint.NewResourceManager()
		}
		s.AggregatedDiscoveryGroupManager = manager
		s.AggregatedLegacyDiscoveryGroupManager = discoveryendpoint.NewResourceManager()
	}
	for {
		if c.JSONPatchMaxCopyBytes <= 0 {
			break
		}
		existing := atomic.LoadInt64(&jsonpatch.AccumulatedCopySizeLimit)
		if existing > 0 && existing < c.JSONPatchMaxCopyBytes {
			break
		}
		if atomic.CompareAndSwapInt64(&jsonpatch.AccumulatedCopySizeLimit, existing, c.JSONPatchMaxCopyBytes) {
			break
		}
	}

	// first add poststarthooks from delegated targets
	for k, v := range delegationTarget.PostStartHooks() {
		s.postStartHooks[k] = v
	}

	for k, v := range delegationTarget.PreShutdownHooks() {
		s.preShutdownHooks[k] = v
	}

	// add poststarthooks that were preconfigured.  Using the add method will give us an error if the same name has already been registered.
	for name, preconfiguredPostStartHook := range c.PostStartHooks {
		if err := s.AddPostStartHook(name, preconfiguredPostStartHook.hook); err != nil {
			return nil, err
		}
	}

	// register mux signals from the delegated server
	for k, v := range delegationTarget.MuxAndDiscoveryCompleteSignals() {
		if err := s.RegisterMuxAndDiscoveryCompleteSignal(k, v); err != nil {
			return nil, err
		}
	}

	genericApiServerHookName := "generic-apiserver-start-informers"
	if c.SharedInformerFactory != nil {
		if !s.isPostStartHookRegistered(genericApiServerHookName) {
			err := s.AddPostStartHook(genericApiServerHookName, func(context PostStartHookContext) error {
				c.SharedInformerFactory.Start(context.StopCh)
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
		// TODO: Once we get rid of /healthz consider changing this to post-start-hook.
		err := s.AddReadyzChecks(healthz.NewInformerSyncHealthz(c.SharedInformerFactory))
		if err != nil {
			return nil, err
		}
	}

	const priorityAndFairnessConfigConsumerHookName = "priority-and-fairness-config-consumer"
	if s.isPostStartHookRegistered(priorityAndFairnessConfigConsumerHookName) {
	} else if c.FlowControl != nil {
		err := s.AddPostStartHook(priorityAndFairnessConfigConsumerHookName, func(context PostStartHookContext) error {
			go c.FlowControl.Run(context.StopCh)
			return nil
		})
		if err != nil {
			return nil, err
		}
		// TODO(yue9944882): plumb pre-shutdown-hook for request-management system?
	} else {
		klog.V(3).Infof("Not requested to run hook %s", priorityAndFairnessConfigConsumerHookName)
	}

	// Add PostStartHooks for maintaining the watermarks for the Priority-and-Fairness and the Max-in-Flight filters.
	if c.FlowControl != nil {
		const priorityAndFairnessFilterHookName = "priority-and-fairness-filter"
		if !s.isPostStartHookRegistered(priorityAndFairnessFilterHookName) {
			err := s.AddPostStartHook(priorityAndFairnessFilterHookName, func(context PostStartHookContext) error {
				genericfilters.StartPriorityAndFairnessWatermarkMaintenance(context.StopCh)
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
	} else {
		const maxInFlightFilterHookName = "max-in-flight-filter"
		if !s.isPostStartHookRegistered(maxInFlightFilterHookName) {
			err := s.AddPostStartHook(maxInFlightFilterHookName, func(context PostStartHookContext) error {
				genericfilters.StartMaxInFlightWatermarkMaintenance(context.StopCh)
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
	}

	// Add PostStartHook for maintenaing the object count tracker.
	if c.StorageObjectCountTracker != nil {
		const storageObjectCountTrackerHookName = "storage-object-count-tracker-hook"
		if !s.isPostStartHookRegistered(storageObjectCountTrackerHookName) {
			if err := s.AddPostStartHook(storageObjectCountTrackerHookName, func(context PostStartHookContext) error {
				go c.StorageObjectCountTracker.RunUntil(context.StopCh)
				return nil
			}); err != nil {
				return nil, err
			}
		}
	}

	for _, delegateCheck := range delegationTarget.HealthzChecks() {
		skip := false
		for _, existingCheck := range c.HealthzChecks {
			if existingCheck.Name() == delegateCheck.Name() {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		s.AddHealthChecks(delegateCheck)
	}
	s.RegisterDestroyFunc(func() {
		if err := c.Config.TracerProvider.Shutdown(context.Background()); err != nil {
			klog.Errorf("failed to shut down tracer provider: %v", err)
		}
	})

	s.listedPathProvider = routes.ListedPathProviders{s.listedPathProvider, delegationTarget}

	installAPI(s, c.Config)

	// use the UnprotectedHandler from the delegation target to ensure that we don't attempt to double authenticator, authorize,
	// or some other part of the filter chain in delegation cases.
	if delegationTarget.UnprotectedHandler() == nil && c.EnableIndex {
		s.Handler.NonGoRestfulMux.NotFoundHandler(routes.IndexLister{
			StatusCode:   http.StatusNotFound,
			PathProvider: s.listedPathProvider,
		})
	}

	return s, nil
}

func BuildHandlerChainWithStorageVersionPrecondition(apiHandler http.Handler, c *Config) http.Handler {
	// WithStorageVersionPrecondition needs the WithRequestInfo to run first
	handler := genericapifilters.WithStorageVersionPrecondition(apiHandler, c.StorageVersionManager, c.Serializer)
	return DefaultBuildHandlerChain(handler, c)
}

// DefaultBuildHandlerChain ✅
func DefaultBuildHandlerChain(apiHandler http.Handler, c *Config) http.Handler {
	handler := filterlatency.TrackCompleted(apiHandler)
	handler = genericapifilters.WithAuthorization(handler, c.Authorization.Authorizer, c.Serializer) // 授权
	handler = filterlatency.TrackStarted(handler, c.TracerProvider, "authorization")

	if c.FlowControl != nil {
		workEstimatorCfg := flowcontrolrequest.DefaultWorkEstimatorConfig()
		requestWorkEstimator := flowcontrolrequest.NewWorkEstimator(
			c.StorageObjectCountTracker.Get, c.FlowControl.GetInterestedWatchCount, workEstimatorCfg)
		handler = filterlatency.TrackCompleted(handler)
		handler = genericfilters.WithPriorityAndFairness(handler, c.LongRunningFunc, c.FlowControl, requestWorkEstimator)
		handler = filterlatency.TrackStarted(handler, c.TracerProvider, "priorityandfairness")
	} else {
		handler = genericfilters.WithMaxInFlightLimit(handler, c.MaxRequestsInFlight, c.MaxMutatingRequestsInFlight, c.LongRunningFunc)
	}

	handler = filterlatency.TrackCompleted(handler)
	handler = genericapifilters.WithImpersonation(handler, c.Authorization.Authorizer, c.Serializer) // 模拟用户请求  // ✅
	handler = filterlatency.TrackStarted(handler, c.TracerProvider, "impersonation")

	handler = filterlatency.TrackCompleted(handler)
	handler = genericapifilters.WithAudit(handler, c.AuditBackend, c.AuditPolicyRuleEvaluator, c.LongRunningFunc) // ✅
	handler = filterlatency.TrackStarted(handler, c.TracerProvider, "audit")

	failedHandler := genericapifilters.Unauthorized(c.Serializer) // 看能不能拿到requestInfo
	failedHandler = genericapifilters.WithFailedAuthenticationAudit(failedHandler, c.AuditBackend, c.AuditPolicyRuleEvaluator)
	failedHandler = filterlatency.TrackCompleted(failedHandler)

	handler = filterlatency.TrackCompleted(handler)
	handler = genericapifilters.WithAuthentication(handler, c.Authentication.Authenticator, failedHandler, c.Authentication.APIAudiences) // ✅ 认证
	handler = filterlatency.TrackStarted(handler, c.TracerProvider, "authentication")

	handler = genericfilters.WithCORS(handler, c.CorsAllowedOriginList, nil, nil, nil, "true") // ✅

	// 将在具有截止日期的上下文中使用go-routine调用其余的请求处理。go-routine可以继续运行，而超时逻辑将向客户端返回超时。
	handler = genericfilters.WithTimeoutForNonLongRunningRequests(handler, c.LongRunningFunc) // ✅

	handler = genericapifilters.WithRequestDeadline(handler, c.AuditBackend, c.AuditPolicyRuleEvaluator, c.LongRunningFunc, c.Serializer, c.RequestTimeout) // ✅

	handler = genericfilters.WithWaitGroup(handler, c.LongRunningFunc, c.HandlerChainWaitGroup) // ✅

	if c.SecureServing != nil && !c.SecureServing.DisableHTTP2 && c.GoawayChance > 0 {
		handler = genericfilters.WithProbabilisticGoaway(handler, c.GoawayChance) // ✅
	}
	handler = genericapifilters.WithWarningRecorder(handler)     // ✅
	handler = genericapifilters.WithCacheControl(handler)        // ✅
	handler = genericfilters.WithHSTS(handler, c.HSTSDirectives) // ✅
	if c.ShutdownSendRetryAfter {
		handler = genericfilters.WithRetryAfter(handler, c.lifecycleSignals.NotAcceptingNewRequest.Signaled()) // ✅ 429 响应码
	}
	handler = genericfilters.WithHTTPLogging(handler) // ✅
	if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.APIServerTracing) {
		handler = genericapifilters.WithTracing(handler, c.TracerProvider) // ✅
	}
	handler = genericapifilters.WithLatencyTrackers(handler)                                                                // ✅
	handler = genericapifilters.WithRequestInfo(handler, c.RequestInfoResolver)                                             // ✅
	handler = genericapifilters.WithRequestReceivedTimestamp(handler)                                                       // ✅
	handler = genericapifilters.WithMuxAndDiscoveryComplete(handler, c.lifecycleSignals.MuxAndDiscoveryComplete.Signaled()) // ✅
	handler = genericfilters.WithPanicRecovery(handler, c.RequestInfoResolver)                                              // ✅
	handler = genericapifilters.WithAuditInit(handler)                                                                      // 注册允许审计的标记位、添加审计ID
	return handler
}

func installAPI(s *GenericAPIServer, c *Config) {
	if c.EnableIndex {
		routes.Index{}.Install(s.listedPathProvider, s.Handler.NonGoRestfulMux)
	}
	if c.EnableProfiling {
		routes.Profiling{}.Install(s.Handler.NonGoRestfulMux)
		if c.EnableContentionProfiling {
			goruntime.SetBlockProfileRate(1)
		}
		// so far, only logging related endpoints are considered valid to add for these debug flags.
		routes.DebugFlags{}.Install(s.Handler.NonGoRestfulMux, "v", routes.StringFlagPutHandler(logs.GlogSetter))
	}

	if c.EnableMetrics {
		if c.EnableProfiling {
			routes.MetricsWithReset{}.Install(s.Handler.NonGoRestfulMux)
			if utilfeature.DefaultFeatureGate.Enabled(features.ComponentSLIs) {
				slis.SLIMetricsWithReset{}.Install(s.Handler.NonGoRestfulMux)
			}
		} else {
			routes.DefaultMetrics{}.Install(s.Handler.NonGoRestfulMux)
			if utilfeature.DefaultFeatureGate.Enabled(features.ComponentSLIs) {
				slis.SLIMetrics{}.Install(s.Handler.NonGoRestfulMux)
			}
		}
	}

	routes.Version{Version: c.Version}.Install(s.Handler.GoRestfulContainer)

	if c.EnableDiscovery {
		if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.AggregatedDiscoveryEndpoint) {
			wrapped := discoveryendpoint.WrapAggregatedDiscoveryToHandler(s.DiscoveryGroupManager, s.AggregatedDiscoveryGroupManager)
			s.Handler.GoRestfulContainer.Add(wrapped.GenerateWebService("/apis", metav1.APIGroupList{})) // 没有走到
		} else {
			// /apis
			s.Handler.GoRestfulContainer.Add(s.DiscoveryGroupManager.WebService()) // ✅  1个
		}
	}
	if c.FlowControl != nil && utilfeature.DefaultFeatureGate.Enabled(genericfeatures.APIPriorityAndFairness) {
		c.FlowControl.Install(s.Handler.NonGoRestfulMux)
	}
}

// NewRequestInfoResolver 根据请求URL分配属性（由审核和授权使用）。
func NewRequestInfoResolver(c *Config) *apirequest.RequestInfoFactory {
	apiPrefixes := sets.NewString(strings.Trim(APIGroupPrefix, "/")) // 所有资源的前缀集合。
	legacyAPIPrefixes := sets.String{}                               // 内置资源的前缀集合
	for legacyAPIPrefix := range c.LegacyAPIGroupPrefixes {
		apiPrefixes.Insert(strings.Trim(legacyAPIPrefix, "/"))
		legacyAPIPrefixes.Insert(strings.Trim(legacyAPIPrefix, "/"))
	}

	return &apirequest.RequestInfoFactory{
		APIPrefixes:          apiPrefixes,
		GrouplessAPIPrefixes: legacyAPIPrefixes,
	}
}

func (s *SecureServingInfo) HostPort() (string, int, error) {
	if s == nil || s.Listener == nil {
		return "", 0, fmt.Errorf("no listener found")
	}
	addr := s.Listener.Addr().String()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("failed to get port from listener address %q: %v", addr, err)
	}
	port, err := utilsnet.ParsePort(portStr, true)
	if err != nil {
		return "", 0, fmt.Errorf("invalid non-numeric port %q", portStr)
	}
	return host, port, nil
}

// AuthorizeClientBearerToken 将验证器和授权器包装在环回验证逻辑中
// 如果指定了环回客户端配置并且它有一个不记名令牌。请注意，如果是authn或authz是nil，这个函数不会添加一个令牌验证器或授权器。
func AuthorizeClientBearerToken(loopback *restclient.Config, authn *AuthenticationInfo, authz *AuthorizationInfo) {
	if loopback == nil || len(loopback.BearerToken) == 0 {
		return
	}
	if authn == nil || authz == nil {
		// prevent nil pointer panic
		return
	}
	if authn.Authenticator == nil || authz.Authorizer == nil {
		// authenticator or authorizer might be nil if we want to bypass authz/authn
		// and we also do nothing in this case.
		return
	}

	privilegedLoopbackToken := loopback.BearerToken
	var uid = uuid.New().String()
	tokens := make(map[string]*user.DefaultInfo)
	tokens[privilegedLoopbackToken] = &user.DefaultInfo{
		Name:   user.APIServerUser,
		UID:    uid,
		Groups: []string{user.SystemPrivilegedGroup},
	}

	tokenAuthenticator := authenticatorfactory.NewFromTokens(tokens, authn.APIAudiences)
	authn.Authenticator = authenticatorunion.New(tokenAuthenticator, authn.Authenticator)
}
