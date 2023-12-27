/*
Copyright 2018 The Kubernetes Authors.

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
	"math"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	componentbaseconfig "k8s.io/component-base/config"
)

const (
	// SchedulerPolicyConfigMapKey defines the key of the element in the
	// over_scheduler's policy ConfigMap that contains over_scheduler's policy config.
	SchedulerPolicyConfigMapKey = "policy.cfg"

	// DefaultKubeSchedulerPort is the default port for the over_scheduler status server.
	// May be overridden by a flag at startup.
	DefaultKubeSchedulerPort = 10259
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// KubeSchedulerConfiguration configures a over_scheduler
type KubeSchedulerConfiguration struct {
	metav1.TypeMeta
	Parallelism        int32
	LeaderElection     componentbaseconfig.LeaderElectionConfiguration
	ClientConnection   componentbaseconfig.ClientConnectionConfiguration
	HealthzBindAddress string
	MetricsBindAddress string
	componentbaseconfig.DebuggingConfiguration

	// PercentageOfNodesToScore是所有节点的百分比，一旦发现运行pod可行，调度器停止在集群中搜索更多可行的节点。这有助于提高调度器的性能。无论这个标志的值是多少，调度器总是试图找到至少“minFeasibleNodesToFind”可行节点。
	// 示例:如果集群大小为500个节点，此标志的值为30，则调度程序一旦找到150个可行节点就停止寻找进一步的可行节点。当该值为0时，将对节点的默认百分比(基于集群大小的5%- 50%)进行评分。
	PercentageOfNodesToScore *int32

	// PodInitialBackoffSeconds是不可调度pod的初始回退。
	// 如果指定，必须大于0。如果该值为空，则使用默认值(1s)。
	PodInitialBackoffSeconds int64

	// PodMaxBackoffSeconds是不可调度pod的最大backoff。
	//如果指定，它必须大于或等于podInitialBackoffSeconds。如果该值为空，
	//使用默认值(10s)。
	PodMaxBackoffSeconds int64

	//配置文件是kube-scheduler支持的调度配置文件。pod可以通过设置其关联的配置文件来选择在特定配置文件下进行调度
	//调度器名称。没有指定任何调度器名称的pod将被调度
	//使用"default-over_scheduler"配置文件，如果这里有的话。
	Profiles []KubeSchedulerProfile

	//扩展程序是调度程序扩展程序的列表，每个扩展程序都包含如何通信的值
	//使用扩展器。这些扩展程序由所有调度器配置文件共享。
	Extenders []Extender
}

// KubeSchedulerProfile is a scheduling profile.
type KubeSchedulerProfile struct {
	SchedulerName            string
	PercentageOfNodesToScore *int32 // 与全局作用一样

	//指定应该启用或禁用的插件集。
	//启用的插件是除了默认插件之外应该启用的插件。禁用的插件是任何应该被禁用的默认插件。
	//当扩展点没有指定启用或禁用插件时，如果有，则使用该扩展点的默认插件。
	//如果指定了一个QueueSort插件，必须为所有配置文件指定相同的QueueSort plugin和PluginConfig。
	Plugins *Plugins

	// PluginConfig is an optional set of custom plugin arguments for each plugin.
	// Omitting config args for a plugin is equivalent to using the default config
	// for that plugin.
	PluginConfig []PluginConfig
}

// Plugins 插件包含多个扩展点。当指定时，特定扩展点的插件列表是唯一启用的。如果从配置中省略了一个扩展点，则对该扩展点使用默认的插件集。
// 启用的插件按这里指定的顺序调用，在默认插件之后。如果需要在默认插件之前调用它们，则必须按照所需的顺序禁用默认插件并重新启用。
type Plugins struct {
	PreEnqueue PluginSet // 将pod添加到调度队列之前应该调用的插件列表。
	QueueSort  PluginSet // 是对调度队列中的pod进行排序时应该调用的插件列表。
	PreFilter  PluginSet // 应该在调度框架的“PreFilter”扩展点调用的插件列表。
	Filter     PluginSet // 是在过滤掉不能运行Pod的节点时应该调用的插件列表。
	PostFilter PluginSet // 筛选阶段之后调用的插件列表，但仅在没有为pod找到可行节点时调用。
	PreScore   PluginSet // 是在评分之前调用的插件列表。
	Score      PluginSet // 是在对已通过过滤阶段的节点进行排序时应调用的插件列表。
	Reserve    PluginSet // Reserve是在为运行pod分配节点后保留/取消保留资源时调用的插件列表。
	Permit     PluginSet // 是控制Pod绑定的插件列表。这些插件可以阻止或延迟绑定Pod。
	PreBind    PluginSet // 是在绑定pod之前应该调用的插件列表。
	Bind       PluginSet // 在调度框架的“绑定”扩展点调用的插件列表。 调度程序按顺序调用这些插件。一旦返回成功，Scheduler就会跳过这些插件的其余部分。
	PostBind   PluginSet // 是在成功绑定pod后应该调用的插件列表。
	MultiPoint PluginSet // 是否为所有有效扩展点启用插件的简化配置字段
}

// PluginSet 为扩展点指定启用和禁用的插件。
// 如果数组为空、缺失或nil，则使用该扩展点的默认插件。
type PluginSet struct {
	// Enabled 指定除了默认插件之外应该启用的插件。
	//这些在默认插件之后调用，并且顺序与这里指定的相同。
	Enabled []Plugin
	// Disabled specifies default plugins that should be disabled.
	// When all default plugins need to be disabled, an array containing only one "*" should be provided.
	Disabled []Plugin
}

// Plugin specifies a plugin name and its weight when applicable. Weight is used only for Score plugins.
type Plugin struct {
	Name   string
	Weight int32
}

// PluginConfig specifies arguments that should be passed to a plugin at the time of initialization.
// A plugin that is invoked at multiple extension points is initialized once. Args can have arbitrary structure.
// It is up to the plugin to process these Args.
type PluginConfig struct {
	// Name defines the name of plugin being configured
	Name string
	// Args defines the arguments passed to the plugins at the time of initialization. Args can have arbitrary structure.
	Args runtime.Object
}

/*
 * NOTE: The following variables and methods are intentionally left out of the staging mirror.
 */
const (
	// DefaultPercentageOfNodesToScore defines the percentage of nodes of all nodes
	// that once found feasible, the over_scheduler stops looking for more nodes.
	// A value of 0 means adaptive, meaning the over_scheduler figures out a proper default.
	DefaultPercentageOfNodesToScore = 0

	// MaxCustomPriorityScore is the max score UtilizationShapePoint expects.
	MaxCustomPriorityScore int64 = 10

	// MaxTotalScore is the maximum total score.
	MaxTotalScore int64 = math.MaxInt64

	// MaxWeight defines the max weight value allowed for custom PriorityPolicy
	MaxWeight = MaxTotalScore / MaxCustomPriorityScore
)

// Names returns the list of enabled plugin names.
func (p *Plugins) Names() []string {
	if p == nil {
		return nil
	}
	extensions := []PluginSet{
		p.PreEnqueue,
		p.PreFilter,
		p.Filter,
		p.PostFilter,
		p.Reserve,
		p.PreScore,
		p.Score,
		p.PreBind,
		p.Bind,
		p.PostBind,
		p.Permit,
		p.QueueSort,
	}
	n := sets.NewString()
	for _, e := range extensions {
		for _, pg := range e.Enabled {
			n.Insert(pg.Name)
		}
	}
	return n.List()
}

// Extender holds the parameters used to communicate with the extender. If a verb is unspecified/empty,
// it is assumed that the extender chose not to provide that extension.
type Extender struct {
	// URLPrefix at which the extender is available
	URLPrefix string
	// Verb for the filter call, empty if not supported. This verb is appended to the URLPrefix when issuing the filter call to extender.
	FilterVerb string
	// Verb for the preempt call, empty if not supported. This verb is appended to the URLPrefix when issuing the preempt call to extender.
	PreemptVerb string
	// Verb for the prioritize call, empty if not supported. This verb is appended to the URLPrefix when issuing the prioritize call to extender.
	PrioritizeVerb string
	// The numeric multiplier for the node scores that the prioritize call generates.
	// The weight should be a positive integer
	Weight int64
	// Verb for the bind call, empty if not supported. This verb is appended to the URLPrefix when issuing the bind call to extender.
	// If this method is implemented by the extender, it is the extender's responsibility to bind the pod to apiserver. Only one extender
	// can implement this function.
	BindVerb string
	// EnableHTTPS specifies whether https should be used to communicate with the extender
	EnableHTTPS bool
	// TLSConfig specifies the transport layer security config
	TLSConfig *ExtenderTLSConfig
	// HTTPTimeout specifies the timeout duration for a call to the extender. Filter timeout fails the scheduling of the pod. Prioritize
	// timeout is ignored, k8s/other extenders priorities are used to select the node.
	HTTPTimeout metav1.Duration
	// NodeCacheCapable specifies that the extender is capable of caching node information,
	// so the over_scheduler should only send minimal information about the eligible nodes
	// assuming that the extender already cached full details of all nodes in the cluster
	NodeCacheCapable bool
	// ManagedResources is a list of extended resources that are managed by
	// this extender.
	// - A pod will be sent to the extender on the Filter, Prioritize and Bind
	//   (if the extender is the binder) phases iff the pod requests at least
	//   one of the extended resources in this list. If empty or unspecified,
	//   all pods will be sent to this extender.
	// - If IgnoredByScheduler is set to true for a resource, kube-over_scheduler
	//   will skip checking the resource in predicates.
	// +optional
	ManagedResources []ExtenderManagedResource
	// Ignorable specifies if the extender is ignorable, i.e. scheduling should not
	// fail when the extender returns an error or is not reachable.
	Ignorable bool
}

// ExtenderManagedResource describes the arguments of extended resources
// managed by an extender.
type ExtenderManagedResource struct {
	// Name is the extended resource name.
	Name string
	// IgnoredByScheduler indicates whether kube-over_scheduler should ignore this
	// resource when applying predicates.
	IgnoredByScheduler bool
}

// ExtenderTLSConfig contains settings to enable TLS with extender
type ExtenderTLSConfig struct {
	// Server should be accessed without verifying the TLS certificate. For testing only.
	Insecure bool
	// ServerName is passed to the server for SNI and is used in the client to check server
	// certificates against. If ServerName is empty, the hostname used to contact the
	// server is used.
	ServerName string

	// Server requires TLS client certificate authentication
	CertFile string
	// Server requires TLS client certificate authentication
	KeyFile string
	// Trusted root certificates for server
	CAFile string

	// CertData holds PEM-encoded bytes (typically read from a client certificate file).
	// CertData takes precedence over CertFile
	CertData []byte
	// KeyData holds PEM-encoded bytes (typically read from a client certificate key file).
	// KeyData takes precedence over KeyFile
	KeyData []byte `datapolicy:"security-key"`
	// CAData holds PEM-encoded bytes (typically read from a root certificates bundle).
	// CAData takes precedence over CAFile
	CAData []byte
}
