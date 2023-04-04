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

// Package options contains all of the primary arguments for a kubelet.
package options

import (
	"fmt"
	_ "net/http/pprof" // Enable pprof HTTP handlers.
	"strings"

	"github.com/spf13/pflag"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	cliflag "k8s.io/component-base/cli/flag"
	logsapi "k8s.io/component-base/logs/api/v1"
	"k8s.io/kubelet/config/v1beta1"
	kubeletapis "k8s.io/kubelet/pkg/apis"
	"k8s.io/kubernetes/pkg/cluster/ports"
	"k8s.io/kubernetes/pkg/features"
	kubeletconfig "k8s.io/kubernetes/pkg/kubelet/apis/config"
	kubeletscheme "k8s.io/kubernetes/pkg/kubelet/apis/config/scheme"
	kubeletconfigvalidation "k8s.io/kubernetes/pkg/kubelet/apis/config/validation"
	"k8s.io/kubernetes/pkg/kubelet/config"
	kubetypes "k8s.io/kubernetes/pkg/kubelet/types"
	utilflag "k8s.io/kubernetes/pkg/util/flag"
)

const defaultRootDir = "/var/lib/kubelet"

type KubeletFlags struct {
	KubeConfig          string // /etc/kubernetes/kubelet.conf
	KubeletConfigFile   string // /var/lib/kubelet/config.yaml
	BootstrapKubeconfig string // /etc/kubernetes/bootstrap-kubelet.conf

	HostnameOverride string // 是用于标识kubelet的主机名，而不是实际主机名。
	NodeIP           string

	config.ContainerRuntimeOptions

	CertDirectory   string
	CloudProvider   string // +optional
	CloudConfigFile string // +optional
	RootDirectory   string // 是放置kubelet文件（卷挂载等）的目录路径。

	WindowsService       bool   // 如果kubelet在Windows上作为服务运行，则应将其设置为true。其对应的标志仅在Windows构建中注册。
	WindowsPriorityClass string // kubelet 进程优先级

	RemoteRuntimeEndpoint                              string
	RemoteImageEndpoint                                string
	ExperimentalMounterPath                            string            // 是挂载程序二进制文件的路径。如果要使用默认的挂载路径，请留空。
	ExperimentalNodeAllocatableIgnoreEvictionThreshold bool              // 如果设置了此标志，则在计算节点可分配性时，将避免包含“EvictionHard”限制。
	NodeLabels                                         map[string]string // Node Labels是在注册节点时添加的节点标签。

	LockFilePath         string // kubelet 文件独占锁
	ExitOnLockContention bool   // kubelet侦听锁文件上的inotify事件，当另一个进程尝试打开该文件时，释放它并退出。

	MinimumGCAge            metav1.Duration // DEPRECATED FLAGS // minimumGCAge是完成的容器在进行垃圾回收之前的最小时间。
	MaxPerPodContainerCount int32           // 是每个容器要保留的旧实例的最大数量。每个容器占用一些磁盘空间。
	MaxContainerCount       int32           // 是要全局保留的容器旧实例的最大数量。每个容器占用一些磁盘空间。
	MasterServiceNamespace  string          // 是应从中将kubernetes主服务注入到pod的命名空间。
	// registerSchedulable tells the kubelet to register the node as
	// schedulable. Won't have any effect if register-node is false.
	// DEPRECATED: use registerWithTaints instead
	RegisterSchedulable bool
	// 如果设置了此标志，则指示kubelet将自已终止的pod的卷 依然保持挂载到节点。这对于调试与卷相关的问题可能很有用。
	KeepTerminatedPodVolumes bool
	// SeccompDefault启用使用“RuntimeDefault”作为节点上所有工作负载的默认seccomp配置文件。// 要使用此标志，必须启用相应的SeccompDefault功能门。
	SeccompDefault bool
}

func NewKubeletFlags() *KubeletFlags {
	return &KubeletFlags{
		ContainerRuntimeOptions: *NewContainerRuntimeOptions(),
		CertDirectory:           "/var/lib/kubelet/pki",
		RootDirectory:           defaultRootDir,
		MasterServiceNamespace:  metav1.NamespaceDefault,
		MaxContainerCount:       -1,
		MaxPerPodContainerCount: 1,
		MinimumGCAge:            metav1.Duration{Duration: 0},
		RegisterSchedulable:     true,
		NodeLabels:              make(map[string]string),
	}
}

// ValidateKubeletFlags 验证Kubelet的配置标志，并在它们无效时返回错误。
func ValidateKubeletFlags(f *KubeletFlags) error {
	unknownLabels := sets.NewString()
	invalidLabelErrs := make(map[string][]string)
	for k, v := range f.NodeLabels {
		if isKubernetesLabel(k) && !kubeletapis.IsKubeletLabel(k) {
			unknownLabels.Insert(k)
		}

		if errs := validation.IsQualifiedName(k); len(errs) > 0 {
			invalidLabelErrs[k] = append(invalidLabelErrs[k], errs...)
		}
		if errs := validation.IsValidLabelValue(v); len(errs) > 0 {
			invalidLabelErrs[v] = append(invalidLabelErrs[v], errs...)
		}
	}
	if len(unknownLabels) > 0 {
		return fmt.Errorf("unknown 'kubernetes.io' or 'k8s.io' labels specified with --node-labels: %v\n--node-labels in the 'kubernetes.io' namespace must begin with an allowed prefix (%s) or be in the specifically allowed set (%s)", unknownLabels.List(), strings.Join(kubeletapis.KubeletLabelNamespaces(), ", "), strings.Join(kubeletapis.KubeletLabels(), ", "))
	}
	if len(invalidLabelErrs) > 0 {
		labelErrs := []string{}
		for k, v := range invalidLabelErrs {
			labelErrs = append(labelErrs, fmt.Sprintf("'%s' - %s", k, strings.Join(v, ", ")))
		}
		return fmt.Errorf("invalid node labels: %s", strings.Join(labelErrs, "; "))
	}

	if f.SeccompDefault && !utilfeature.DefaultFeatureGate.Enabled(features.SeccompDefault) {
		return fmt.Errorf("the SeccompDefault feature gate must be enabled in order to use the --seccomp-default flag")
	}

	if f.ContainerRuntime != kubetypes.RemoteContainerRuntime {
		return fmt.Errorf("unsupported CRI runtime: %q, only %q is currently supported", f.ContainerRuntime, kubetypes.RemoteContainerRuntime)
	}

	// Note: maybe we can test it for being a valid socket address as an additional improvement.
	// The only problem with it will be that some setups may not specify 'unix://' prefix.
	// So just check empty for back compat.
	if f.RemoteRuntimeEndpoint == "" {
		return fmt.Errorf("the container runtime endpoint address was not specified or empty, use --container-runtime-endpoint to set")
	}

	return nil
}

func isKubernetesLabel(key string) bool {
	namespace := getLabelNamespace(key)
	if namespace == "kubernetes.io" || strings.HasSuffix(namespace, ".kubernetes.io") {
		return true
	}
	if namespace == "k8s.io" || strings.HasSuffix(namespace, ".k8s.io") {
		return true
	}
	return false
}

func getLabelNamespace(key string) string {
	if parts := strings.SplitN(key, "/", 2); len(parts) == 2 {
		return parts[0]
	}
	return ""
}

// NewKubeletConfiguration 将创建具有默认值的新KubeletConfiguration。
func NewKubeletConfiguration() (*kubeletconfig.KubeletConfiguration, error) {
	scheme, _, err := kubeletscheme.NewSchemeAndCodecs()
	if err != nil {
		return nil, err
	}
	versioned := &v1beta1.KubeletConfiguration{}
	scheme.Default(versioned)
	config := &kubeletconfig.KubeletConfiguration{}
	if err := scheme.Convert(versioned, config, nil); err != nil {
		return nil, err
	}
	applyLegacyDefaults(config)
	return config, nil
}

// applyLegacyDefaults将遗留的默认值应用于KubeletConfiguration，以
// 保留命令行API。这用于构建默认的 KubeletConfiguration
// 在第一轮标志解析之前。
func applyLegacyDefaults(kc *kubeletconfig.KubeletConfiguration) {
	// --anonymous-auth
	kc.Authentication.Anonymous.Enabled = true
	// --authentication-token-webhook
	kc.Authentication.Webhook.Enabled = false
	// --authorization-mode
	kc.Authorization.Mode = kubeletconfig.KubeletAuthorizationModeAlwaysAllow
	// --read-only-port
	kc.ReadOnlyPort = ports.KubeletReadOnlyPort
}

// KubeletServer encapsulates all of the parameters necessary for starting up
// a kubelet. These can either be set via command line or directly.
type KubeletServer struct {
	KubeletFlags
	kubeletconfig.KubeletConfiguration
}

// NewKubeletServer will create a new KubeletServer with default values.
func NewKubeletServer() (*KubeletServer, error) {
	config, err := NewKubeletConfiguration()
	if err != nil {
		return nil, err
	}
	return &KubeletServer{
		KubeletFlags:         *NewKubeletFlags(),
		KubeletConfiguration: *config,
	}, nil
}

// ValidateKubeletServer validates configuration of KubeletServer and returns an error if the input configuration is invalid.
func ValidateKubeletServer(s *KubeletServer) error {
	// please add any KubeletConfiguration validation to the kubeletconfigvalidation.ValidateKubeletConfiguration function
	if err := kubeletconfigvalidation.ValidateKubeletConfiguration(&s.KubeletConfiguration, utilfeature.DefaultFeatureGate); err != nil {
		return err
	}
	if err := ValidateKubeletFlags(&s.KubeletFlags); err != nil {
		return err
	}
	return nil
}

// AddFlags adds flags for a specific KubeletServer to the specified FlagSet
func (s *KubeletServer) AddFlags(fs *pflag.FlagSet) {
	s.KubeletFlags.AddFlags(fs)
	AddKubeletConfigFlags(fs, &s.KubeletConfiguration)
}

// AddFlags adds flags for a specific KubeletFlags to the specified FlagSet
func (f *KubeletFlags) AddFlags(mainfs *pflag.FlagSet) {
	// 用于覆盖/etc/kubernetes/kubelet.conf里的参数
	fs := pflag.NewFlagSet("", pflag.ExitOnError)
	defer func() {
		// Unhide deprecated flags. We want deprecated flags to show in Kubelet help.
		// We have some hidden flags, but we might as well unhide these when they are deprecated,
		// as silently deprecating and removing (even hidden) things is unkind to people who use them.
		fs.VisitAll(func(f *pflag.Flag) {
			if len(f.Deprecated) > 0 {
				f.Hidden = false
			}
		})
		mainfs.AddFlagSet(fs)
	}()

	f.ContainerRuntimeOptions.AddFlags(fs)
	f.addOSFlags(fs)

	fs.StringVar(&f.KubeletConfigFile, "config", f.KubeletConfigFile, "Kubelet将从该文件加载其初始配置。路径可以是绝对或相对的；相对路径从Kubelet的当前工作目录开始。省略此标志以使用内置的默认配置值。命令行标志将覆盖此文件中的配置。")
	fs.StringVar(&f.KubeConfig, "kubeconfig", f.KubeConfig, "kubeconfig文件的路径，指定如何连接到API服务器。提供--kubeconfig启用API服务器模式，省略--kubeconfig启用独立模式。")
	fs.StringVar(&f.BootstrapKubeconfig, "bootstrap-kubeconfig", f.BootstrapKubeconfig, "用于获取kubelet客户端证书的kubeconfig文件的路径。如果--kubeconfig指定的文件不存在，则使用引导kubeconfig从API服务器请求客户端证书。成功后，将向--kubeconfig指定的路径写入引用生成的客户端证书和密钥的kubeconfig文件。客户端证书和密钥文件将存储在--cert-dir指向的目录中。")
	fs.StringVar(&f.HostnameOverride, "hostname-override", f.HostnameOverride, "如果非空，将使用此字符串作为标识，而不是实际主机名。如果设置了--cloud-provider，则使用云提供程序确定节点的名称（请参阅云提供程序文档以确定主机名是否以及如何使用）")
	fs.StringVar(&f.NodeIP, "node-ip", f.NodeIP, "节点的IP地址（或逗号分隔的双栈IP地址）。如果未设置，kubelet将使用节点的默认IPv4地址（如果有），或者如果没有IPv4地址，则使用其默认IPv6地址。您可以传递“::”以使其优先使用默认IPv6地址而不是默认IPv4地址。")
	fs.StringVar(&f.CertDirectory, "cert-dir", f.CertDirectory, "TLS证书所在的目录。如果提供了--tls-cert-file和--tls-private-key-file，则将忽略此标志。")
	fs.StringVar(&f.RootDirectory, "root-dir", f.RootDirectory, "管理kubelet文件（卷挂载等）的目录路径。")
	fs.StringVar(&f.RemoteRuntimeEndpoint, "container-runtime-endpoint", f.RemoteRuntimeEndpoint, "远程运行时服务的终结点。Linux支持Unix域套接字，而Windows支持npipe和tcp终结点。示例：“unix:///path/to/runtime.sock”，“npipe:////./pipe/runtime”。")
	fs.StringVar(&f.RemoteImageEndpoint, "image-service-endpoint", f.RemoteImageEndpoint, "远程镜像服务的地址。如果未指定，则默认情况下将与--container-runtime-endpoint相同。Linux支持Unix域套接字，而Windows支持npipe和tcp终结点。示例：“unix:///path/to/runtime.sock”，“npipe:////./pipe/runtime”")

	// 实验性标志。
	bindableNodeLabels := cliflag.ConfigurationMap(f.NodeLabels)
	fs.Var(&bindableNodeLabels, "node-labels", fmt.Sprintf("<警告：Alpha功能>在注册节点时添加的标签。标签必须是用“,”分隔的键=值对。在“kubernetes.io”命名空间中的标签必须以允许的前缀（%s）开头或在特定允许的集合（%s）中。", strings.Join(kubeletapis.KubeletLabelNamespaces(), ", "), strings.Join(kubeletapis.KubeletLabels(), ", ")))
	fs.StringVar(&f.LockFilePath, "lock-file", f.LockFilePath, "<警告：Alpha功能> kubelet用作锁文件的文件路径。")
	fs.BoolVar(&f.ExitOnLockContention, "exit-on-lock-contention", f.ExitOnLockContention, "kubelet是否应在锁文件争用时退出。")
	fs.BoolVar(&f.SeccompDefault, "seccomp-default", f.SeccompDefault, "<警告：Beta功能> 启用使用“RuntimeDefault”作为所有工作负载的默认seccomp配置文件。必须启用SeccompDefault功能门以允许此标志，默认情况下禁用该标志。")

	// DEPRECATED FLAGS
	//fs.DurationVar(&f.MinimumGCAge.Duration, "minimum-container-ttl-duration", f.MinimumGCAge.Duration, "Minimum age for a finished container before it is garbage collected.  Examples: '300ms', '10s' or '2h45m'")
	//fs.MarkDeprecated("minimum-container-ttl-duration", "Use --eviction-hard or --eviction-soft instead. Will be removed in a future version.")
	//fs.Int32Var(&f.MaxPerPodContainerCount, "maximum-dead-containers-per-container", f.MaxPerPodContainerCount, "Maximum number of old instances to retain per container.  Each container takes up some disk space.")
	//fs.MarkDeprecated("maximum-dead-containers-per-container", "Use --eviction-hard or --eviction-soft instead. Will be removed in a future version.")
	//fs.Int32Var(&f.MaxContainerCount, "maximum-dead-containers", f.MaxContainerCount, "Maximum number of old instances of containers to retain globally.  Each container takes up some disk space. To disable, set to a negative number.")
	//fs.MarkDeprecated("maximum-dead-containers", "Use --eviction-hard or --eviction-soft instead. Will be removed in a future version.")
	//fs.StringVar(&f.MasterServiceNamespace, "master-service-namespace", f.MasterServiceNamespace, "将kubernetes主服务注入pod的命名空间")
	//fs.MarkDeprecated("master-service-namespace", "将被移除")
	//fs.BoolVar(&f.RegisterSchedulable, "register-schedulable", f.RegisterSchedulable, "Register the node as schedulable. Won't have any effect if register-node is false.")
	//fs.MarkDeprecated("register-schedulable", "will be removed in a future version")
	//fs.BoolVar(&f.KeepTerminatedPodVolumes, "keep-terminated-pod-volumes", f.KeepTerminatedPodVolumes, "Keep terminated pod volumes mounted to the node after the pod terminates.  Can be useful for debugging volume related issues.")
	//fs.MarkDeprecated("keep-terminated-pod-volumes", "will be removed in a future version")
	//fs.StringVar(&f.ExperimentalMounterPath, "experimental-mounter-path", f.ExperimentalMounterPath, "[实验性]挂载程序二进制文件的路径。如果要使用默认的挂载，请留空。")
	//fs.MarkDeprecated("experimental-mounter-path", "将在1.25或更高版本中删除，以便使用CSI。")
	//fs.StringVar(&f.CloudProvider, "cloud-provider", f.CloudProvider, "云服务提供商。设置为空字符串以在没有云提供程序的情况下运行。如果设置了，云提供程序确定节点的名称（请参阅云提供程序文档以确定主机名是否以及如何使用）。")
	//fs.MarkDeprecated("cloud-provider", "将在1.25或更高版本中删除，以取代从Kubelet中删除云提供程序代码。")
	//fs.StringVar(&f.CloudConfigFile, "cloud-config", f.CloudConfigFile, "云提供程序配置文件的路径。空字符串表示没有配置文件。")
	//fs.MarkDeprecated("cloud-config", "将在1.25或更高版本中删除，以取代从Kubelet中删除云提供程序代码。")
	//fs.BoolVar(&f.ExperimentalNodeAllocatableIgnoreEvictionThreshold, "experimental-allocatable-ignore-eviction", f.ExperimentalNodeAllocatableIgnoreEvictionThreshold, "当设置为“true”时，将在计算节点可分配性时忽略硬驱逐阈值。. See https://kubernetes.io/docs/tasks/administer-cluster/reserve-compute-resources/ for more details. [default=false]")
	//fs.MarkDeprecated("experimental-allocatable-ignore-eviction", "will be removed in 1.25 or later.")
}

// AddKubeletConfigFlags 将特定的kubeletconfig.KubeletConfiguration的标志添加到指定的FlagSet中。
func AddKubeletConfigFlags(mainfs *pflag.FlagSet, c *kubeletconfig.KubeletConfiguration) {
	fs := pflag.NewFlagSet("", pflag.ExitOnError)
	defer func() {
		// All KubeletConfiguration flags are now deprecated, and any new flags that point to
		// KubeletConfiguration fields are deprecated-on-creation. When removing flags at the end
		// of their deprecation period, be careful to check that they have *actually* been deprecated
		// members of the KubeletConfiguration for the entire deprecation period:
		// e.g. if a flag was added after this deprecation function, it may not be at the end
		// of its lifetime yet, even if the rest are.
		deprecated := "This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information."
		// Some flags are permanently (?) meant to be available. In
		// Kubernetes 1.23, the following options were added to
		// LoggingConfiguration (long-term goal, more complete
		// configuration file) but deprecating the flags seemed
		// premature.
		notDeprecated := map[string]bool{
			"v":                   true,
			"vmodule":             true,
			"log-flush-frequency": true,
		}
		fs.VisitAll(func(f *pflag.Flag) {
			if notDeprecated[f.Name] {
				return
			}
			f.Deprecated = deprecated
		})
		mainfs.AddFlagSet(fs)
	}()

	fs.BoolVar(&c.EnableServer, "enable-server", c.EnableServer, "启用Kubelet的服务器")

	fs.BoolVar(&c.FailSwapOn, "fail-swap-on", c.FailSwapOn, "如果节点上启用了SWAP空间，则使Kubelet无法启动。")
	fs.StringVar(&c.StaticPodPath, "pod-manifest-path", c.StaticPodPath, "包含要运行的静态pod文件的目录路径，或单个静态pod文件的路径。以点开头的文件将被忽略。")
	fs.DurationVar(&c.SyncFrequency.Duration, "sync-frequency", c.SyncFrequency.Duration, "同步运行容器和配置之间的最大时间间隔。")
	fs.DurationVar(&c.FileCheckFrequency.Duration, "file-check-frequency", c.FileCheckFrequency.Duration, "检查配置文件以获取新数据的时间。")
	fs.DurationVar(&c.HTTPCheckFrequency.Duration, "http-check-frequency", c.HTTPCheckFrequency.Duration, "检查http以获取新数据的时间。")
	fs.StringVar(&c.StaticPodURL, "manifest-url", c.StaticPodURL, "用于从某个地址获取要运行的静态pod。")
	fs.Var(cliflag.NewColonSeparatedMultimapStringString(&c.StaticPodURLHeader), "manifest-url-header", "在访问提供给--manifest-url的URL时要使用的逗号分隔的HTTP标头列表。具有相同名称的多个标头将按提供的相同顺序添加。可以重复使用此标志。例如：--manifest-url-header 'a:hello,b:again,c:world' --manifest-url-header 'b:beautiful'")
	fs.Var(&utilflag.IPVar{Val: &c.Address}, "address", "Kubelet要服务的IP地址（设置为“0.0.0.0”或“::”以在所有接口和IP族上进行侦听）")
	fs.Int32Var(&c.Port, "port", c.Port, "Kubelet要服务的端口。")
	fs.Int32Var(&c.ReadOnlyPort, "read-only-port", c.ReadOnlyPort, "Kubelet要在其上提供只读端口，没有身份验证/授权（设置为0以禁用）")

	// Authentication
	fs.BoolVar(&c.Authentication.Anonymous.Enabled, "anonymous-auth", c.Authentication.Anonymous.Enabled, "启用对Kubelet服务器的匿名请求。未被其他身份验证方法拒绝的请求将被视为匿名请求。匿名请求的用户名为system:anonymous，组名为system:unauthenticated。")
	fs.BoolVar(&c.Authentication.Webhook.Enabled, "authentication-token-webhook", c.Authentication.Webhook.Enabled, "使用TokenReview API来确定承载令牌的身份验证。")
	fs.DurationVar(&c.Authentication.Webhook.CacheTTL.Duration, "authentication-token-webhook-cache-ttl", c.Authentication.Webhook.CacheTTL.Duration, "缓存来自Webhook令牌验证器的响应的持续时间。")
	fs.StringVar(&c.Authentication.X509.ClientCAFile, "client-ca-file", c.Authentication.X509.ClientCAFile, "如果设置，通过由client-ca-file中的任何一个机构签名的客户端证书呈现的任何请求都将使用与客户端证书的CommonName相对应的身份进行身份验证。")

	// Authorization
	fs.StringVar((*string)(&c.Authorization.Mode), "authorization-mode", string(c.Authorization.Mode), "Kubelet服务器的授权模式。有效选项为AlwaysAllow或Webhook。Webhook模式使用SubjectAccessReview API来确定授权。")
	fs.DurationVar(&c.Authorization.Webhook.CacheAuthorizedTTL.Duration, "authorization-webhook-cache-authorized-ttl", c.Authorization.Webhook.CacheAuthorizedTTL.Duration, "缓存来自Webhook授权程序的“已授权”响应的持续时间。")
	fs.DurationVar(&c.Authorization.Webhook.CacheUnauthorizedTTL.Duration, "authorization-webhook-cache-unauthorized-ttl", c.Authorization.Webhook.CacheUnauthorizedTTL.Duration, "缓存来自Webhook授权程序的“未授权”响应的持续时间。")

	fs.StringVar(&c.TLSCertFile, "tls-cert-file", c.TLSCertFile, "包含用于提供HTTPS的x509证书的文件（如果有中间证书，则连接在服务器证书之后）。如果未提供--tls-cert-file和--tls-private-key-file，则会为公共地址生成自签名证书和密钥，并保存到传递给--cert-dir的目录中。")
	fs.StringVar(&c.TLSPrivateKeyFile, "tls-private-key-file", c.TLSPrivateKeyFile, "包含与--tls-cert-file匹配的x509私钥的文件。")
	fs.BoolVar(&c.ServerTLSBootstrap, "rotate-server-certificates", c.ServerTLSBootstrap, "通过在证书过期接近时从kube-apiserver请求新证书来自动请求和轮换kubelet服务证书。需要启用RotateKubeletServerCertificate 开关，并批准提交的CSR对象。")

	tlsCipherPreferredValues := cliflag.PreferredTLSCipherNames() // 反回由crypto/tls实现的密码套件名称列表。
	tlsCipherInsecureValues := cliflag.InsecureTLSCipherNames()   // 返回由crypto/tls实现的具有安全问题的密码套件名称列表。
	fs.StringSliceVar(&c.TLSCipherSuites, "tls-cipher-suites", c.TLSCipherSuites,
		"服务器的逗号分隔的密码套件列表。如果省略，则将使用默认的Go密码套件。\n"+
			"Preferred values: "+strings.Join(tlsCipherPreferredValues, ", ")+". \n"+
			"Insecure values: "+strings.Join(tlsCipherInsecureValues, ", ")+".")
	tlsPossibleVersions := cliflag.TLSPossibleVersions()
	fs.StringVar(&c.TLSMinVersion, "tls-min-version", c.TLSMinVersion, "支持的最低TLS版本。Possible values: "+strings.Join(tlsPossibleVersions, ", "))
	fs.BoolVar(&c.RotateCertificates, "rotate-certificates", c.RotateCertificates, "<警告：Beta功能>通过在证书过期接近时从kube-apiserver请求新证书，自动轮换kubelet客户端证书。")

	fs.Int32Var(&c.RegistryPullQPS, "registry-qps", c.RegistryPullQPS, "如果> 0，则将注册表拉取QPS限制为此值。如果为0，则无限制。")
	fs.Int32Var(&c.RegistryBurst, "registry-burst", c.RegistryBurst, "突发式拉取的最大大小，临时允许拉取突发到此数字，同时仍不超过registry-qps。仅在--registry-qps> 0时使用。")
	fs.Int32Var(&c.EventRecordQPS, "event-qps", c.EventRecordQPS, "限制事件创建的QPS。数字必须>= 0。如果为0，将使用DefaultQPS：5。")
	fs.Int32Var(&c.EventBurst, "event-burst", c.EventBurst, "突发式事件记录的最大大小，临时允许事件记录突发到此数字，同时仍不超过event-qps。数字必须>= 0。如果为0，将使用DefaultBurst：10。")

	fs.BoolVar(&c.EnableDebuggingHandlers, "enable-debugging-handlers", c.EnableDebuggingHandlers, "启用用于日志收集和本地运行容器和命令的服务器端点。")
	fs.BoolVar(&c.EnableContentionProfiling, "contention-profiling", c.EnableContentionProfiling, "Enable lock contention profiling, if profiling is enabled")
	fs.Int32Var(&c.HealthzPort, "healthz-port", c.HealthzPort, "The port of the localhost healthz endpoint (set to 0 to disable)")
	fs.Var(&utilflag.IPVar{Val: &c.HealthzBindAddress}, "healthz-bind-address", "The IP address for the healthz server to serve on (set to '0.0.0.0' or '::' for listening in all interfaces and IP families)")
	fs.Int32Var(&c.OOMScoreAdj, "oom-score-adj", c.OOMScoreAdj, "The oom-score-adj value for kubelet process. Values must be within the range [-1000, 1000]")
	fs.StringVar(&c.ClusterDomain, "cluster-domain", c.ClusterDomain, "Domain for this cluster.  If set, kubelet will configure all containers to search this domain in addition to the host's search domains")

	fs.StringVar(&c.VolumePluginDir, "volume-plugin-dir", c.VolumePluginDir, "The full path of the directory in which to search for additional third party volume plugins")
	fs.StringSliceVar(&c.ClusterDNS, "cluster-dns", c.ClusterDNS, "Comma-separated list of DNS server IP address.  This value is used for containers DNS server in case of Pods with \"dnsPolicy=ClusterFirst\". Note: all DNS servers appearing in the list MUST serve the same set of records otherwise name resolution within the cluster may not work correctly. There is no guarantee as to which DNS server may be contacted for name resolution.")
	fs.DurationVar(&c.StreamingConnectionIdleTimeout.Duration, "streaming-connection-idle-timeout", c.StreamingConnectionIdleTimeout.Duration, "Maximum time a streaming connection can be idle before the connection is automatically closed. 0 indicates no timeout. Example: '5m'. Note: All connections to the kubelet server have a maximum duration of 4 hours.")
	fs.DurationVar(&c.NodeStatusUpdateFrequency.Duration, "node-status-update-frequency", c.NodeStatusUpdateFrequency.Duration, "Specifies how often kubelet posts node status to master. Note: be cautious when changing the constant, it must work with nodeMonitorGracePeriod in nodecontroller.")
	fs.DurationVar(&c.ImageMinimumGCAge.Duration, "minimum-image-ttl-duration", c.ImageMinimumGCAge.Duration, "Minimum age for an unused image before it is garbage collected.  Examples: '300ms', '10s' or '2h45m'.")
	fs.Int32Var(&c.ImageGCHighThresholdPercent, "image-gc-high-threshold", c.ImageGCHighThresholdPercent, "The percent of disk usage after which image garbage collection is always run. Values must be within the range [0, 100], To disable image garbage collection, set to 100. ")
	fs.Int32Var(&c.ImageGCLowThresholdPercent, "image-gc-low-threshold", c.ImageGCLowThresholdPercent, "The percent of disk usage before which image garbage collection is never run. Lowest disk usage to garbage collect to. Values must be within the range [0, 100] and should not be larger than that of --image-gc-high-threshold.")
	fs.DurationVar(&c.VolumeStatsAggPeriod.Duration, "volume-stats-agg-period", c.VolumeStatsAggPeriod.Duration, "Specifies interval for kubelet to calculate and cache the volume disk usage for all pods and volumes.  To disable volume calculations, set to a negative number.")
	fs.Var(cliflag.NewMapStringBool(&c.FeatureGates), "feature-gates", "一组键值对，用于描述alpha/experimental特性的开关 。 "+
		"Options are:\n"+strings.Join(utilfeature.DefaultFeatureGate.KnownFeatures(), "\n"))
	fs.StringVar(&c.KubeletCgroups, "kubelet-cgroups", c.KubeletCgroups, "Optional absolute name of cgroups to create and run the Kubelet in.")
	fs.StringVar(&c.SystemCgroups, "system-cgroups", c.SystemCgroups, "Optional absolute name of cgroups in which to place all non-kernel processes that are not already inside a cgroup under '/'. Empty for no container. Rolling back the flag requires a reboot.")

	fs.StringVar(&c.ProviderID, "provider-id", c.ProviderID, "Unique identifier for identifying the node in a machine database, i.e cloudprovider")

	fs.BoolVar(&c.CgroupsPerQOS, "cgroups-per-qos", c.CgroupsPerQOS, "Enable creation of QoS cgroup hierarchy, if true top level QoS and pod cgroups are created.")
	fs.StringVar(&c.CgroupDriver, "cgroup-driver", c.CgroupDriver, "Driver that the kubelet uses to manipulate cgroups on the host.  Possible values: 'cgroupfs', 'systemd'")
	fs.StringVar(&c.CgroupRoot, "cgroup-root", c.CgroupRoot, "Optional root cgroup to use for pods. This is handled by the container runtime on a best effort basis. Default: '', which means use the container runtime default.")
	fs.StringVar(&c.CPUManagerPolicy, "cpu-manager-policy", c.CPUManagerPolicy, "CPU Manager policy to use. Possible values: 'none', 'static'.")
	fs.Var(cliflag.NewMapStringStringNoSplit(&c.CPUManagerPolicyOptions), "cpu-manager-policy-options", "A set of key=value CPU Manager policy options to use, to fine tune their behaviour. If not supplied, keep the default behaviour.")
	fs.DurationVar(&c.CPUManagerReconcilePeriod.Duration, "cpu-manager-reconcile-period", c.CPUManagerReconcilePeriod.Duration, "<Warning: Alpha feature> CPU Manager reconciliation period. Examples: '10s', or '1m'. If not supplied, defaults to 'NodeStatusUpdateFrequency'")
	fs.Var(cliflag.NewMapStringString(&c.QOSReserved), "qos-reserved", "<Warning: Alpha feature> A set of ResourceName=Percentage (e.g. memory=50%) pairs that describe how pod resource requests are reserved at the QoS level. Currently only memory is supported. Requires the QOSReserved feature gate to be enabled.")
	fs.StringVar(&c.TopologyManagerPolicy, "topology-manager-policy", c.TopologyManagerPolicy, "Topology Manager policy to use. Possible values: 'none', 'best-effort', 'restricted', 'single-numa-node'.")
	fs.DurationVar(&c.RuntimeRequestTimeout.Duration, "runtime-request-timeout", c.RuntimeRequestTimeout.Duration, "Timeout of all runtime requests except long running request - pull, logs, exec and attach. When timeout exceeded, kubelet will cancel the request, throw out an error and retry later.")
	fs.StringVar(&c.HairpinMode, "hairpin-mode", c.HairpinMode, "How should the kubelet setup hairpin NAT. This allows endpoints of a Service to loadbalance back to themselves if they should try to access their own Service. Valid values are \"promiscuous-bridge\", \"hairpin-veth\" and \"none\".")
	fs.Int32Var(&c.MaxPods, "max-pods", c.MaxPods, "Number of Pods that can run on this Kubelet.")

	fs.StringVar(&c.PodCIDR, "pod-cidr", c.PodCIDR, "The CIDR to use for pod IP addresses, only used in standalone mode.  In cluster mode, this is obtained from the master. For IPv6, the maximum number of IP's allocated is 65536")
	fs.Int64Var(&c.PodPidsLimit, "pod-max-pids", c.PodPidsLimit, "Set the maximum number of processes per pod.  If -1, the kubelet defaults to the node allocatable pid capacity.")

	fs.StringVar(&c.ResolverConfig, "resolv-conf", c.ResolverConfig, "Resolver configuration file used as the basis for the container DNS resolution configuration.")

	fs.BoolVar(&c.RunOnce, "runonce", c.RunOnce, "If true, exit after spawning pods from static pod files or remote urls. Exclusive with --enable-server")

	fs.BoolVar(&c.CPUCFSQuota, "cpu-cfs-quota", c.CPUCFSQuota, "Enable CPU CFS quota enforcement for containers that specify CPU limits")
	fs.DurationVar(&c.CPUCFSQuotaPeriod.Duration, "cpu-cfs-quota-period", c.CPUCFSQuotaPeriod.Duration, "Sets CPU CFS quota period value, cpu.cfs_period_us, defaults to Linux Kernel default")
	fs.BoolVar(&c.EnableControllerAttachDetach, "enable-controller-attach-detach", c.EnableControllerAttachDetach, "Enables the Attach/Detach controller to manage attachment/detachment of volumes scheduled to this node, and disables kubelet from executing any attach/detach operations")
	fs.BoolVar(&c.MakeIPTablesUtilChains, "make-iptables-util-chains", c.MakeIPTablesUtilChains, "If true, kubelet will ensure iptables utility rules are present on host.")
	fs.Int32Var(&c.IPTablesMasqueradeBit, "iptables-masquerade-bit", c.IPTablesMasqueradeBit, "The bit of the fwmark space to mark packets for SNAT. Must be within the range [0, 31]. Please match this parameter with corresponding parameter in kube-proxy.")
	fs.Int32Var(&c.IPTablesDropBit, "iptables-drop-bit", c.IPTablesDropBit, "The bit of the fwmark space to mark packets for dropping. Must be within the range [0, 31].")
	fs.StringVar(&c.ContainerLogMaxSize, "container-log-max-size", c.ContainerLogMaxSize, "<Warning: Beta feature> Set the maximum size (e.g. 10Mi) of container log file before it is rotated. This flag can only be used with --container-runtime=remote.")
	fs.Int32Var(&c.ContainerLogMaxFiles, "container-log-max-files", c.ContainerLogMaxFiles, "<Warning: Beta feature> Set the maximum number of container log files that can be present for a container. The number must be >= 2. This flag can only be used with --container-runtime=remote.")
	fs.StringSliceVar(&c.AllowedUnsafeSysctls, "allowed-unsafe-sysctls", c.AllowedUnsafeSysctls, "Comma-separated whitelist of unsafe sysctls or unsafe sysctl patterns (ending in *). Use these at your own risk.")

	fs.Int32Var(&c.NodeStatusMaxImages, "node-status-max-images", c.NodeStatusMaxImages, "The maximum number of images to report in Node.Status.Images. If -1 is specified, no cap will be applied.")
	fs.BoolVar(&c.KernelMemcgNotification, "kernel-memcg-notification", c.KernelMemcgNotification, "If enabled, the kubelet will integrate with the kernel memcg notification to determine if memory eviction thresholds are crossed rather than polling.")
	fs.BoolVar(&c.LocalStorageCapacityIsolation, "local-storage-capacity-isolation", c.LocalStorageCapacityIsolation, "If true, local ephemeral storage isolation is enabled. Otherwise, local storage isolation feature will be disabled")

	// Flags intended for testing, not recommended used in production environments.
	fs.Int64Var(&c.MaxOpenFiles, "max-open-files", c.MaxOpenFiles, "Number of files that can be opened by Kubelet process.")

	fs.StringVar(&c.ContentType, "kube-api-content-type", c.ContentType, "Content type of requests sent to apiserver.")
	fs.Int32Var(&c.KubeAPIQPS, "kube-api-qps", c.KubeAPIQPS, "QPS to use while talking with kubernetes apiserver. The number must be >= 0. If 0 will use DefaultQPS: 5. Doesn't cover events and node heartbeat apis which rate limiting is controlled by a different set of flags")
	fs.Int32Var(&c.KubeAPIBurst, "kube-api-burst", c.KubeAPIBurst, "Burst to use while talking with kubernetes apiserver. The number must be >= 0. If 0 will use DefaultBurst: 10. Doesn't cover events and node heartbeat apis which rate limiting is controlled by a different set of flags")
	fs.BoolVar(&c.SerializeImagePulls, "serialize-image-pulls", c.SerializeImagePulls, "Pull images one at a time. We recommend *not* changing the default value on nodes that run docker daemon with version < 1.9 or an Aufs storage backend. Issue #10959 has more details.")

	fs.Var(cliflag.NewLangleSeparatedMapStringString(&c.EvictionHard), "eviction-hard", "A set of eviction thresholds (e.g. memory.available<1Gi) that if met would trigger a pod eviction.")
	fs.Var(cliflag.NewLangleSeparatedMapStringString(&c.EvictionSoft), "eviction-soft", "A set of eviction thresholds (e.g. memory.available<1.5Gi) that if met over a corresponding grace period would trigger a pod eviction.")
	fs.Var(cliflag.NewMapStringString(&c.EvictionSoftGracePeriod), "eviction-soft-grace-period", "A set of eviction grace periods (e.g. memory.available=1m30s) that correspond to how long a soft eviction threshold must hold before triggering a pod eviction.")
	fs.DurationVar(&c.EvictionPressureTransitionPeriod.Duration, "eviction-pressure-transition-period", c.EvictionPressureTransitionPeriod.Duration, "Duration for which the kubelet has to wait before transitioning out of an eviction pressure condition.")
	fs.Int32Var(&c.EvictionMaxPodGracePeriod, "eviction-max-pod-grace-period", c.EvictionMaxPodGracePeriod, "Maximum allowed grace period (in seconds) to use when terminating pods in response to a soft eviction threshold being met.  If negative, defer to pod specified value.")
	fs.Var(cliflag.NewMapStringString(&c.EvictionMinimumReclaim), "eviction-minimum-reclaim", "A set of minimum reclaims (e.g. imagefs.available=2Gi) that describes the minimum amount of resource the kubelet will reclaim when performing a pod eviction if that resource is under pressure.")
	fs.Int32Var(&c.PodsPerCore, "pods-per-core", c.PodsPerCore, "Number of Pods per core that can run on this Kubelet. The total number of Pods on this Kubelet cannot exceed max-pods, so max-pods will be used if this calculation results in a larger number of Pods allowed on the Kubelet. A value of 0 disables this limit.")
	fs.BoolVar(&c.ProtectKernelDefaults, "protect-kernel-defaults", c.ProtectKernelDefaults, "Default kubelet behaviour for kernel tuning. If set, kubelet errors if any of kernel tunables is different than kubelet defaults.")
	fs.StringVar(&c.ReservedSystemCPUs, "reserved-cpus", c.ReservedSystemCPUs, "A comma-separated list of CPUs or CPU ranges that are reserved for system and kubernetes usage. This specific list will supersede cpu counts in --system-reserved and --kube-reserved.")
	fs.StringVar(&c.TopologyManagerScope, "topology-manager-scope", c.TopologyManagerScope, "Scope to which topology hints applied. Topology Manager collects hints from Hint Providers and applies them to defined scope to ensure the pod admission. Possible values: 'container', 'pod'.")
	fs.Var(cliflag.NewMapStringStringNoSplit(&c.TopologyManagerPolicyOptions), "topology-manager-policy-options", "A set of key=value Topology Manager policy options to use, to fine tune their behaviour. If not supplied, keep the default behaviour.")
	// Node Allocatable Flags
	fs.Var(cliflag.NewMapStringString(&c.SystemReserved), "system-reserved", "A set of ResourceName=ResourceQuantity (e.g. cpu=200m,memory=500Mi,ephemeral-storage=1Gi) pairs that describe resources reserved for non-kubernetes components. Currently only cpu, memory and local ephemeral storage for root file system are supported. See https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/ for more detail. [default=none]")
	fs.Var(cliflag.NewMapStringString(&c.KubeReserved), "kube-reserved", "A set of ResourceName=ResourceQuantity (e.g. cpu=200m,memory=500Mi,ephemeral-storage=1Gi) pairs that describe resources reserved for kubernetes system components. Currently only cpu, memory and local ephemeral storage for root file system are supported. See https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/ for more detail. [default=none]")
	fs.StringSliceVar(&c.EnforceNodeAllocatable, "enforce-node-allocatable", c.EnforceNodeAllocatable, "A comma separated list of levels of node allocatable enforcement to be enforced by kubelet. Acceptable options are 'none', 'pods', 'system-reserved', and 'kube-reserved'. If the latter two options are specified, '--system-reserved-cgroup' and '--kube-reserved-cgroup' must also be set, respectively. If 'none' is specified, no additional options should be set. See https://kubernetes.io/docs/tasks/administer-cluster/reserve-compute-resources/ for more details.")
	fs.StringVar(&c.SystemReservedCgroup, "system-reserved-cgroup", c.SystemReservedCgroup, "Absolute name of the top level cgroup that is used to manage non-kubernetes components for which compute resources were reserved via '--system-reserved' flag. Ex. '/system-reserved'. [default='']")
	fs.StringVar(&c.KubeReservedCgroup, "kube-reserved-cgroup", c.KubeReservedCgroup, "Absolute name of the top level cgroup that is used to manage kubernetes components for which compute resources were reserved via '--kube-reserved' flag. Ex. '/kube-reserved'. [default='']")
	logsapi.AddFlags(&c.Logging, fs)

	// Memory Manager Flags
	fs.StringVar(&c.MemoryManagerPolicy, "memory-manager-policy", c.MemoryManagerPolicy, "Memory Manager policy to use. Possible values: 'None', 'Static'.")
	fs.Var(&utilflag.ReservedMemoryVar{Value: &c.ReservedMemory}, "reserved-memory", "A comma separated list of memory reservations for NUMA nodes. (e.g. --reserved-memory 0:memory=1Gi,hugepages-1M=2Gi --reserved-memory 1:memory=2Gi). The total sum for each memory type should be equal to the sum of kube-reserved, system-reserved and eviction-threshold. See https://kubernetes.io/docs/tasks/administer-cluster/memory-manager/#reserved-memory-flag for more details.")

	fs.BoolVar(&c.RegisterNode, "register-node", c.RegisterNode, "Register the node with the apiserver. If --kubeconfig is not provided, this flag is irrelevant, as the Kubelet won't have an apiserver to register with.")

	fs.Var(&utilflag.RegisterWithTaintsVar{Value: &c.RegisterWithTaints}, "register-with-taints", "Register the node with the given list of taints (comma separated \"<key>=<value>:<effect>\"). No-op if register-node is false.")
}
