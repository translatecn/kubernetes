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

package options

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/registry/generic"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/healthz"
	"k8s.io/apiserver/pkg/server/options/encryptionconfig"
	kmsconfigcontroller "k8s.io/apiserver/pkg/server/options/encryptionconfig/controller"
	serverstorage "k8s.io/apiserver/pkg/server/storage"
	"k8s.io/apiserver/pkg/storage/storagebackend"
	storagefactory "k8s.io/apiserver/pkg/storage/storagebackend/factory"
	flowcontrolrequest "k8s.io/apiserver/pkg/util/flowcontrol/request"
	"k8s.io/klog/v2"
)

type EtcdOptions struct {
	EtcdServersOverrides    []string
	DefaultStorageMediaType string   // 后台存储的数据类型
	DeleteCollectionWorkers int      //
	EnableGarbageCollection bool     //
	EnableWatchCache        bool     // 是否启用监听缓存
	DefaultWatchCacheSize   int      // 0禁用
	WatchCacheSizes         []string // 表示对给定etcd资源的重写

	// The value of Paging on StorageConfig will be overridden by the
	// calculated feature gate value.
	StorageConfig storagebackend.Config //

	EncryptionProviderConfigFilepath        string // 加密提供者配置文件路径
	EncryptionProviderConfigAutomaticReload bool   // 是否启用,默认不开启

	complete               bool // 在使用Apply方法之前,保护必须通过Complete初始化的字段.
	resourceTransformers   encryptionconfig.ResourceTransformers
	kmsPluginHealthzChecks []healthz.HealthChecker
	SkipHealthEndpoints    bool
}

var storageTypes = sets.NewString(
	storagebackend.StorageTypeETCD3,
)

func NewEtcdOptions(backendConfig *storagebackend.Config) *EtcdOptions {
	options := &EtcdOptions{
		StorageConfig:           *backendConfig,
		DefaultStorageMediaType: "application/json",
		DeleteCollectionWorkers: 1,
		EnableGarbageCollection: true,
		EnableWatchCache:        true,
		DefaultWatchCacheSize:   100,
	}
	options.StorageConfig.CountMetricPollPeriod = time.Minute
	return options
}

// Validate 👌🏻
func (s *EtcdOptions) Validate() []error {
	if s == nil {
		return nil
	}

	allErrors := []error{}
	if len(s.StorageConfig.Transport.ServerList) == 0 {
		allErrors = append(allErrors, fmt.Errorf("--etcd-servers must be specified"))
	}

	if s.StorageConfig.Type != storagebackend.StorageTypeUnset && !storageTypes.Has(s.StorageConfig.Type) {
		allErrors = append(allErrors, fmt.Errorf("--storage-backend invalid, allowed values: %s. If not specified, it will default to 'etcd3'", strings.Join(storageTypes.List(), ", ")))
	}

	for _, override := range s.EtcdServersOverrides {
		tokens := strings.Split(override, "#")
		if len(tokens) != 2 {
			allErrors = append(allErrors, fmt.Errorf("--etcd-servers-overrides invalid, must be of format: group/resource#servers, where servers are URLs, semicolon separated"))
			continue
		}

		apiresource := strings.Split(tokens[0], "/")
		if len(apiresource) != 2 {
			allErrors = append(allErrors, fmt.Errorf("--etcd-servers-overrides invalid, must be of format: group/resource#servers, where servers are URLs, semicolon separated"))
			continue
		}

	}

	if len(s.EncryptionProviderConfigFilepath) == 0 && s.EncryptionProviderConfigAutomaticReload {
		allErrors = append(allErrors, fmt.Errorf("--encryption-provider-config-automatic-reload must be set with --encryption-provider-config"))
	}

	return allErrors
}

// AddFlags adds flags related to etcd storage for a specific APIServer to the specified FlagSet
func (s *EtcdOptions) AddFlags(fs *pflag.FlagSet) {
	_ = NewEtcdOptions
	if s == nil {
		return
	}
	fs.StringSliceVar(&s.EtcdServersOverrides, "etcd-servers-overrides", s.EtcdServersOverrides, "覆盖每组资源etcd服务器,逗号分隔.单独重写格式:group/resource#servers,其中servers是url,分号分隔")
	fs.StringVar(&s.DefaultStorageMediaType, "storage-media-type", s.DefaultStorageMediaType, "后端存储时的数据类型.某些资源或存储后端可能只支持特定的媒体类型,并将忽略此设置.支持的类型: [application/json, application/yaml, application/vnd.kubernetes.protobuf]")
	fs.IntVar(&s.DeleteCollectionWorkers, "delete-collection-workers", s.DeleteCollectionWorkers, "删除etcd无用数据的worker数")
	fs.BoolVar(&s.EnableGarbageCollection, "enable-garbage-collector", s.EnableGarbageCollection, "启用通用垃圾回收器.必须与 kube-controller-manager 的相应标志同步.")
	fs.BoolVar(&s.EnableWatchCache, "watch-cache", s.EnableWatchCache, "在apisserver中启用监视缓存")
	fs.IntVar(&s.DefaultWatchCacheSize, "default-watch-cache-size", s.DefaultWatchCacheSize, "默认的watch缓存大小.如果为零,watch缓存将被禁用")
	fs.MarkDeprecated("default-watch-cache-size", "watch缓存是自动大小,这个标志将被删除在未来的版本")
	fs.StringSliceVar(&s.WatchCacheSizes, "watch-cache-sizes", s.WatchCacheSizes, "注意某些资源(pod、节点等)的缓存大小设置,用逗号分隔.此选项仅对内置于apiserver中的资源有意义")
	fs.StringVar(&s.StorageConfig.Type, "storage-backend", s.StorageConfig.Type, "用于持久性的存储后端.选项:'etcd3'(默认值).")
	fs.StringSliceVar(&s.StorageConfig.Transport.ServerList, "etcd-servers", s.StorageConfig.Transport.ServerList, "要连接的etcd服务器列表(scheme://ip:port),逗号分隔.")
	fs.StringVar(&s.StorageConfig.Prefix, "etcd-prefix", s.StorageConfig.Prefix, "etcd中所有资源路径的前缀.")
	fs.StringVar(&s.StorageConfig.Transport.KeyFile, "etcd-keyfile", s.StorageConfig.Transport.KeyFile, "用于保护etcd通信的SSL密钥文件.")
	fs.StringVar(&s.StorageConfig.Transport.CertFile, "etcd-certfile", s.StorageConfig.Transport.CertFile, "用于etcd通信安全的SSL认证文件.")
	fs.StringVar(&s.StorageConfig.Transport.TrustedCAFile, "etcd-cafile", s.StorageConfig.Transport.TrustedCAFile, "SSL证书颁发机构文件,用于保护etcd通信.")
	fs.DurationVar(&s.StorageConfig.CompactionInterval, "etcd-compaction-interval", s.StorageConfig.CompactionInterval, "压缩请求的间隔.如果是0,表示apiserver的压缩请求被禁用.")
	fs.DurationVar(&s.StorageConfig.CountMetricPollPeriod, "etcd-count-metric-poll-period", s.StorageConfig.CountMetricPollPeriod, "对每种类型的资源数量轮询etcd的频率.0禁用度量收集.")
	fs.DurationVar(&s.StorageConfig.DBMetricPollInterval, "etcd-db-metric-poll-interval", s.StorageConfig.DBMetricPollInterval, "轮询etcd和更新度量的请求间隔.0禁用度量收集")
	fs.DurationVar(&s.StorageConfig.HealthcheckTimeout, "etcd-healthcheck-timeout", s.StorageConfig.HealthcheckTimeout, "检查etcd运行状况时使用的超时.")
	fs.DurationVar(&s.StorageConfig.ReadycheckTimeout, "etcd-readycheck-timeout", s.StorageConfig.ReadycheckTimeout, "检查etcd准备就绪时使用的超时")
	fs.Int64Var(&s.StorageConfig.LeaseManagerConfig.ReuseDurationSeconds, "lease-reuse-duration-seconds", s.StorageConfig.LeaseManagerConfig.ReuseDurationSeconds, "每个租约被重用的时间(以秒为单位).较低的值可以避免大量对象重用同一租期.请注意,过小的值可能会导致存储层的性能问题.")
	fs.StringVar(&s.EncryptionProviderConfigFilepath, "encryption-provider-config", s.EncryptionProviderConfigFilepath, "包含用于在etcd中存储secret的加密程序的配置文件")
	fs.BoolVar(&s.EncryptionProviderConfigAutomaticReload, "encryption-provider-config-automatic-reload", s.EncryptionProviderConfigAutomaticReload,
		"确定在磁盘内容更改时 --encryption-provider-config设置的文件是否应自动重新加载.将此设置为true将禁用通过API服务器healthz端点唯一识别不同KMS插件的能力.")

}

// Complete 在使用Apply方法之前,必须精确地调用一次.它负责设置必须创建一次并在多个调用(如存储转换器)之间重用的对象.
// 这个方法会改变接收者(EtcdOptions).它绝不能改变输入.
func (s *EtcdOptions) Complete(
	storageObjectCountTracker flowcontrolrequest.StorageObjectCountTracker,
	stopCh <-chan struct{},
	addPostStartHook func(name string, hook server.PostStartHookFunc) error,
) error {
	if s == nil {
		return nil
	}

	if s.complete {
		return fmt.Errorf("EtcdOptions.Complete called more than once")
	}

	if len(s.EncryptionProviderConfigFilepath) != 0 {
		ctxTransformers, closeTransformers := wait.ContextForChannel(stopCh)
		ctxServer, _ := wait.ContextForChannel(stopCh) // 这里显式地忽略cancel,因为我们不拥有服务器的生命周期

		encryptionConfiguration, err := encryptionconfig.LoadEncryptionConfig(s.EncryptionProviderConfigFilepath, s.EncryptionProviderConfigAutomaticReload, ctxTransformers.Done())
		if err != nil {
			// in case of error, we want to close partially initialized (if any) transformers
			closeTransformers()
			return err
		}

		// enable kms hot reload controller only if the config file is set to be automatically reloaded
		if s.EncryptionProviderConfigAutomaticReload {
			// with reload=true we will always have 1 health check
			if len(encryptionConfiguration.HealthChecks) != 1 {
				// in case of error, we want to close partially initialized (if any) transformers
				closeTransformers()
				return fmt.Errorf("failed to start kms encryption config hot reload controller. only 1 health check should be available when reload is enabled")
			}

			dynamicTransformers := encryptionconfig.NewDynamicTransformers(encryptionConfiguration.Transformers, encryptionConfiguration.HealthChecks[0], closeTransformers, encryptionConfiguration.KMSCloseGracePeriod)

			s.resourceTransformers = dynamicTransformers
			s.kmsPluginHealthzChecks = []healthz.HealthChecker{dynamicTransformers}

			// add post start hook to start hot reload controller
			// adding this hook here will ensure that it gets configured exactly once
			err = addPostStartHook(
				"start-encryption-provider-config-automatic-reload",
				func(hookContext server.PostStartHookContext) error {
					kmsConfigController := kmsconfigcontroller.NewDynamicKMSEncryptionConfiguration(
						"kms-encryption-config",
						s.EncryptionProviderConfigFilepath,
						dynamicTransformers,
						encryptionConfiguration.EncryptionFileContentHash,
						ctxServer.Done(),
					)

					go kmsConfigController.Run(ctxServer)

					return nil
				},
			)
			if err != nil {
				// in case of error, we want to close partially initialized (if any) transformers
				closeTransformers()
				return fmt.Errorf("failed to add post start hook for kms encryption config hot reload controller: %w", err)
			}
		} else {
			s.resourceTransformers = encryptionconfig.StaticTransformers(encryptionConfiguration.Transformers)
			s.kmsPluginHealthzChecks = encryptionConfiguration.HealthChecks
		}
	}

	s.StorageConfig.StorageObjectCountTracker = storageObjectCountTracker

	s.complete = true

	return nil
}

// ApplyTo mutates the provided server.Config.  It must never mutate the receiver (EtcdOptions).
func (s *EtcdOptions) ApplyTo(c *server.Config) error {
	if s == nil {
		return nil
	}

	return s.ApplyWithStorageFactoryTo(&SimpleStorageFactory{StorageConfig: s.StorageConfig}, c)
}

// ApplyWithStorageFactoryTo ✅
func (s *EtcdOptions) ApplyWithStorageFactoryTo(factory serverstorage.StorageFactory, c *server.Config) error {
	if s == nil {
		return nil
	}

	if !s.complete {
		return fmt.Errorf("EtcdOptions.Apply called without completion")
	}

	if !s.SkipHealthEndpoints {
		if err := s.addEtcdHealthEndpoint(c); err != nil {
			return err
		}
	}

	if s.resourceTransformers != nil {
		factory = &transformerStorageFactory{
			delegate:             factory,
			resourceTransformers: s.resourceTransformers,
		}
	}

	c.RESTOptionsGetter = &StorageFactoryRestOptionsFactory{Options: *s, StorageFactory: factory}
	return nil
}

// ✅
func (s *EtcdOptions) addEtcdHealthEndpoint(c *server.Config) error {
	healthCheck, err := storagefactory.CreateHealthCheck(s.StorageConfig, c.DrainedNotify())
	if err != nil {
		return err
	}
	c.AddHealthChecks(healthz.NamedCheck("etcd", func(r *http.Request) error {
		return healthCheck()
	}))

	readyCheck, err := storagefactory.CreateReadyCheck(s.StorageConfig, c.DrainedNotify())
	if err != nil {
		return err
	}
	c.AddReadyzChecks(healthz.NamedCheck("etcd-readiness", func(r *http.Request) error {
		return readyCheck()
	}))

	c.AddHealthChecks(s.kmsPluginHealthzChecks...)

	return nil
}

type StorageFactoryRestOptionsFactory struct {
	Options        EtcdOptions
	StorageFactory serverstorage.StorageFactory
}

func (f *StorageFactoryRestOptionsFactory) GetRESTOptions(resource schema.GroupResource) (generic.RESTOptions, error) {
	storageConfig, err := f.StorageFactory.NewConfig(resource)
	if err != nil {
		return generic.RESTOptions{}, fmt.Errorf("unable to find storage destination for %v, due to %v", resource, err.Error())
	}

	ret := generic.RESTOptions{
		StorageConfig:             storageConfig,
		Decorator:                 generic.UndecoratedStorage,
		DeleteCollectionWorkers:   f.Options.DeleteCollectionWorkers,
		EnableGarbageCollection:   f.Options.EnableGarbageCollection,
		ResourcePrefix:            f.StorageFactory.ResourcePrefix(resource),
		CountMetricPollPeriod:     f.Options.StorageConfig.CountMetricPollPeriod,
		StorageObjectCountTracker: f.Options.StorageConfig.StorageObjectCountTracker,
	}

	if f.Options.EnableWatchCache {
		sizes, err := ParseWatchCacheSizes(f.Options.WatchCacheSizes)
		if err != nil {
			return generic.RESTOptions{}, err
		}
		size, ok := sizes[resource]
		if ok && size > 0 {
			klog.Warningf("Dropping watch-cache-size for %v - watchCache size is now dynamic", resource)
		}
		if ok && size <= 0 {
			klog.V(3).InfoS("Not using watch cache", "resource", resource)
			ret.Decorator = generic.UndecoratedStorage
		} else {
			klog.V(3).InfoS("Using watch cache", "resource", resource)
			ret.Decorator = genericregistry.StorageWithCacher()
		}
	}

	return ret, nil
}

// ParseWatchCacheSizes 将缓存大小值列表转换为组资源到所请求大小的映射.
func ParseWatchCacheSizes(cacheSizes []string) (map[schema.GroupResource]int, error) {
	watchCacheSizes := make(map[schema.GroupResource]int)
	for _, c := range cacheSizes {
		tokens := strings.Split(c, "#")
		if len(tokens) != 2 {
			return nil, fmt.Errorf("invalid value of watch cache size: %s", c)
		}

		size, err := strconv.Atoi(tokens[1])
		if err != nil {
			return nil, fmt.Errorf("invalid size of watch cache size: %s", c)
		}
		if size < 0 {
			return nil, fmt.Errorf("watch cache size cannot be negative: %s", c)
		}
		watchCacheSizes[schema.ParseGroupResource(tokens[0])] = size
	}
	return watchCacheSizes, nil
}

// WriteWatchCacheSizes   ParseWatchCacheSizes 的反过程
func WriteWatchCacheSizes(watchCacheSizes map[schema.GroupResource]int) ([]string, error) {
	var cacheSizes []string

	for resource, size := range watchCacheSizes {
		if size < 0 {
			return nil, fmt.Errorf("watch cache size cannot be negative for resource %s", resource)
		}
		cacheSizes = append(cacheSizes, fmt.Sprintf("%s#%d", resource.String(), size))
	}
	return cacheSizes, nil
}

var _ serverstorage.StorageFactory = &SimpleStorageFactory{}

// SimpleStorageFactory provides a StorageFactory implementation that should be used when different
// resources essentially share the same storage config (as defined by the given storagebackend.Config).
// It assumes the resources are stored at a path that is purely based on the schema.GroupResource.
// Users that need flexibility and per resource overrides should use DefaultStorageFactory instead.
type SimpleStorageFactory struct {
	StorageConfig storagebackend.Config
}

func (s *SimpleStorageFactory) NewConfig(resource schema.GroupResource) (*storagebackend.ConfigForResource, error) {
	return s.StorageConfig.ForResource(resource), nil
}

func (s *SimpleStorageFactory) ResourcePrefix(resource schema.GroupResource) string {
	return resource.Group + "/" + resource.Resource
}

func (s *SimpleStorageFactory) Backends() []serverstorage.Backend {
	// nothing should ever call this method but we still provide a functional implementation
	return serverstorage.Backends(s.StorageConfig)
}

var _ serverstorage.StorageFactory = &transformerStorageFactory{}

type transformerStorageFactory struct {
	delegate             serverstorage.StorageFactory
	resourceTransformers encryptionconfig.ResourceTransformers
}

func (t *transformerStorageFactory) NewConfig(resource schema.GroupResource) (*storagebackend.ConfigForResource, error) {
	config, err := t.delegate.NewConfig(resource)
	if err != nil {
		return nil, err
	}

	configCopy := *config
	resourceConfig := configCopy.Config
	resourceConfig.Transformer = t.resourceTransformers.TransformerForResource(resource)
	configCopy.Config = resourceConfig

	return &configCopy, nil
}

func (t *transformerStorageFactory) ResourcePrefix(resource schema.GroupResource) string {
	return t.delegate.ResourcePrefix(resource)
}

func (t *transformerStorageFactory) Backends() []serverstorage.Backend {
	return t.delegate.Backends()
}
