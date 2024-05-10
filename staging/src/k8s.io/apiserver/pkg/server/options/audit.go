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

package options

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"gopkg.in/natefinch/lumberjack.v2"
	"k8s.io/klog/v2"

	"k8s.io/apimachinery/pkg/runtime/schema"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apimachinery/pkg/util/sets"
	auditinternal "k8s.io/apiserver/pkg/apis/audit"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
	"k8s.io/apiserver/pkg/audit"
	"k8s.io/apiserver/pkg/audit/policy"
	"k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/egressselector"
	"k8s.io/apiserver/pkg/util/webhook"
	pluginbuffered "k8s.io/apiserver/plugin/pkg/audit/buffered"
	pluginlog "k8s.io/apiserver/plugin/pkg/audit/log"
	plugintruncate "k8s.io/apiserver/plugin/pkg/audit/truncate"
	pluginwebhook "k8s.io/apiserver/plugin/pkg/audit/webhook"
)

const (
	// Default configuration values for ModeBatch.
	defaultBatchBufferSize = 10000 // Buffer up to 10000 events before starting discarding.
	// These batch parameters are only used by the webhook backend.
	defaultBatchMaxSize       = 400              // Only send up to 400 events at a time.
	defaultBatchMaxWait       = 30 * time.Second // Send events at least twice a minute.
	defaultBatchThrottleQPS   = 10               // Limit the send rate by 10 QPS.
	defaultBatchThrottleBurst = 15               // Allow up to 15 QPS burst.
)

func appendBackend(existing, newBackend audit.Backend) audit.Backend {
	if existing == nil {
		return newBackend
	}
	if newBackend == nil {
		return existing
	}
	return audit.Union(existing, newBackend)
}

type AuditOptions struct {
	PolicyFile     string // 用于过滤捕获的审计事件的配置文件.如果未指定,则提供默认值.
	LogOptions     AuditLogOptions
	WebhookOptions AuditWebhookOptions
}

const (
	ModeBatch          = "batch"           // 审计后端应该在内部缓冲审计事件,在接收到一定数量的事件或经过一定时间后发送批量更新.
	ModeBlocking       = "blocking"        // 审计后端在每次尝试处理一组事件时阻塞.这会导致对API服务器的请求在发送响应之前等待刷新.
	ModeBlockingStrict = "blocking-strict" // 和ModeBlocking是一样的,除了在RequestReceived阶段的审计日志中有一个失败,整个请求到apiserver将失败.
)

var AllowedModes = []string{
	ModeBatch,
	ModeBlocking,
	ModeBlockingStrict,
}

type AuditBatchOptions struct {
	Mode        string                     //后端应该异步批处理事件到webhook后端或后端应该阻止响应? 默认为异步批处理事件.
	BatchConfig pluginbuffered.BatchConfig // 只有在batch模式时使用
}

type AuditTruncateOptions struct {
	// Whether truncating is enabled or not.
	Enabled bool

	// Truncating configuration.
	TruncateConfig plugintruncate.Config
}

// AuditLogOptions 默认情况下确定结构化审计日志的输出.
type AuditLogOptions struct {
	Path            string
	MaxAge          int
	MaxBackups      int
	MaxSize         int
	Format          string
	Compress        bool
	BatchOptions    AuditBatchOptions
	TruncateOptions AuditTruncateOptions
	// API group version used for serializing audit events.
	GroupVersionString string
}

// AuditWebhookOptions webhook的审计事件配置.
type AuditWebhookOptions struct {
	ConfigFile         string               //
	InitialBackoff     time.Duration        //
	BatchOptions       AuditBatchOptions    //
	TruncateOptions    AuditTruncateOptions //
	GroupVersionString string               // --audit-webhook-version=audit.k8s.io/v1
}

// AuditDynamicOptions control the configuration of dynamic backends for audit events
type AuditDynamicOptions struct {
	// Enabled tells whether the dynamic audit capability is enabled.
	Enabled bool

	// Configuration for batching backend. This is currently only used as an override
	// for integration tests
	BatchConfig *pluginbuffered.BatchConfig
}

// NewAuditOptions 👌🏻
func NewAuditOptions() *AuditOptions {
	return &AuditOptions{
		WebhookOptions: AuditWebhookOptions{
			InitialBackoff: pluginwebhook.DefaultInitialBackoffDelay, //初始补偿时间 10s
			BatchOptions: AuditBatchOptions{
				Mode:        ModeBatch,
				BatchConfig: defaultWebhookBatchConfig(),
			},
			TruncateOptions:    NewAuditTruncateOptions(),
			GroupVersionString: "audit.k8s.io/v1",
		},
		LogOptions: AuditLogOptions{
			Format: pluginlog.FormatJson,
			BatchOptions: AuditBatchOptions{
				Mode:        ModeBlocking,
				BatchConfig: defaultLogBatchConfig(),
			},
			TruncateOptions:    NewAuditTruncateOptions(),
			GroupVersionString: "audit.k8s.io/v1",
		},
	}
}

func NewAuditTruncateOptions() AuditTruncateOptions {
	return AuditTruncateOptions{
		Enabled: false,
		TruncateConfig: plugintruncate.Config{
			MaxBatchSize: 10 * 1024 * 1024, // 10MB
			MaxEventSize: 100 * 1024,       // 100KB
		},
	}
}

// Validate 👌🏻
func (o *AuditOptions) Validate() []error {
	if o == nil {
		return nil
	}

	var allErrors []error
	allErrors = append(allErrors, o.LogOptions.Validate()...)
	allErrors = append(allErrors, o.WebhookOptions.Validate()...)

	return allErrors
}

func validateBackendMode(pluginName string, mode string) error {
	for _, m := range AllowedModes {
		if m == mode {
			return nil
		}
	}
	return fmt.Errorf("invalid audit %s mode %s, allowed modes are %q", pluginName, mode, strings.Join(AllowedModes, ","))
}

func validateBackendBatchOptions(pluginName string, options AuditBatchOptions) error {
	if err := validateBackendMode(pluginName, options.Mode); err != nil {
		return err
	}
	if options.Mode != ModeBatch {
		// Don't validate the unused options.
		return nil
	}
	config := options.BatchConfig
	if config.BufferSize <= 0 {
		return fmt.Errorf("invalid audit batch %s buffer size %v, must be a positive number", pluginName, config.BufferSize)
	}
	if config.MaxBatchSize <= 0 {
		return fmt.Errorf("invalid audit batch %s max batch size %v, must be a positive number", pluginName, config.MaxBatchSize)
	}
	if config.ThrottleEnable {
		if config.ThrottleQPS <= 0 {
			return fmt.Errorf("invalid audit batch %s throttle QPS %v, must be a positive number", pluginName, config.ThrottleQPS)
		}
		if config.ThrottleBurst <= 0 {
			return fmt.Errorf("invalid audit batch %s throttle burst %v, must be a positive number", pluginName, config.ThrottleBurst)
		}
	}
	return nil
}

var knownGroupVersions = []schema.GroupVersion{
	auditv1.SchemeGroupVersion,
}

func validateGroupVersionString(groupVersion string) error {
	gv, err := schema.ParseGroupVersion(groupVersion)
	if err != nil {
		return err
	}
	if !knownGroupVersion(gv) {
		return fmt.Errorf("invalid group version, allowed versions are %q", knownGroupVersions)
	}
	if gv != auditv1.SchemeGroupVersion {
		klog.Warningf("%q is deprecated and will be removed in a future release, use %q instead", gv, auditv1.SchemeGroupVersion)
	}
	return nil
}

func knownGroupVersion(gv schema.GroupVersion) bool {
	for _, knownGv := range knownGroupVersions {
		if gv == knownGv {
			return true
		}
	}
	return false
}

func (o *AuditOptions) AddFlags(fs *pflag.FlagSet) {
	if o == nil {
		return
	}

	fs.StringVar(&o.PolicyFile, "audit-policy-file", o.PolicyFile, "定义审计策略配置的文件的路径.")
	o.LogOptions.AddFlags(fs)
	o.LogOptions.BatchOptions.AddFlags(pluginlog.PluginName, fs)
	o.LogOptions.TruncateOptions.AddFlags(pluginlog.PluginName, fs)
	o.WebhookOptions.AddFlags(fs)
	o.WebhookOptions.BatchOptions.AddFlags(pluginwebhook.PluginName, fs)
	o.WebhookOptions.TruncateOptions.AddFlags(pluginwebhook.PluginName, fs)
}

func (o *AuditOptions) ApplyTo(
	c *server.Config,
) error {
	if o == nil {
		return nil
	}
	if c == nil {
		return fmt.Errorf("server config must be non-nil")
	}

	// 1. 构建策略评估器
	evaluator, err := o.newPolicyRuleEvaluator()
	if err != nil {
		return err
	}

	// 2. 构建日志后端
	var logBackend audit.Backend
	w, err := o.LogOptions.getWriter() // ✅
	if err != nil {
		return err
	}
	if w != nil {
		if evaluator == nil {
			klog.V(2).Info("No audit policy file provided, no events will be recorded for log backend")
		} else {
			logBackend = o.LogOptions.newBackend(w)
		}
	}

	// 3. Build webhook backend
	var webhookBackend audit.Backend
	if o.WebhookOptions.enabled() {
		if evaluator == nil {
			klog.V(2).Info("No audit policy file provided, no events will be recorded for webhook backend")
		} else {
			if c.EgressSelector != nil {
				var egressDialer utilnet.DialFunc
				egressDialer, err = c.EgressSelector.Lookup(egressselector.ControlPlane.AsNetworkContext())
				if err != nil {
					return err
				}
				webhookBackend, err = o.WebhookOptions.newUntruncatedBackend(egressDialer)
			} else {
				webhookBackend, err = o.WebhookOptions.newUntruncatedBackend(nil)
			}
			if err != nil {
				return err
			}
		}
	}

	groupVersion, err := schema.ParseGroupVersion(o.WebhookOptions.GroupVersionString) // --audit-webhook-version=audit.k8s.io/v1
	if err != nil {
		return err
	}

	// 4. Apply dynamic options.
	var dynamicBackend audit.Backend
	if webhookBackend != nil {
		// 如果只启用webhook,则将其封装在截断选项中
		dynamicBackend = o.WebhookOptions.TruncateOptions.wrapBackend(webhookBackend, groupVersion)
	}

	// 5. 设置策略规则计算器
	c.AuditPolicyRuleEvaluator = evaluator

	// 6. 将日志后端与webhooks连接起来
	c.AuditBackend = appendBackend(logBackend, dynamicBackend)

	if c.AuditBackend != nil {
		klog.V(2).Infof("使用审计后端: %s", c.AuditBackend)
	}
	return nil
}

func (o *AuditOptions) newPolicyRuleEvaluator() (audit.PolicyRuleEvaluator, error) {
	if o.PolicyFile == "" {
		return nil, nil
	}

	p, err := policy.LoadPolicyFromFile(o.PolicyFile)
	if err != nil {
		return nil, fmt.Errorf("loading audit policy file: %v", err)
	}
	return policy.NewPolicyRuleEvaluator(p), nil
}

func (o *AuditBatchOptions) AddFlags(pluginName string, fs *pflag.FlagSet) {
	fs.StringVar(&o.Mode, fmt.Sprintf("audit-%s-mode", pluginName), o.Mode, "发送审计事件的策略.阻塞表示发送事件应该阻塞服务器响应.批处理使后端异步缓冲和写入事件.已知模式： "+strings.Join(AllowedModes, ",")+".")
	fs.IntVar(&o.BatchConfig.BufferSize, fmt.Sprintf("audit-%s-batch-buffer-size", pluginName), o.BatchConfig.BufferSize, "在批处理和写入之前用于存储事件的缓冲区的大小.仅用于批处理模式.")
	fs.IntVar(&o.BatchConfig.MaxBatchSize, fmt.Sprintf("audit-%s-batch-max-size", pluginName), o.BatchConfig.MaxBatchSize, "批处理的最大大小.仅用于批处理模式.")
	fs.DurationVar(&o.BatchConfig.MaxBatchWait, fmt.Sprintf("audit-%s-batch-max-wait", pluginName), o.BatchConfig.MaxBatchWait, "未达到最大大小的批处理之前强制写入的等待时间量.仅用于批处理模式.")
	fs.BoolVar(&o.BatchConfig.ThrottleEnable, fmt.Sprintf("audit-%s-batch-throttle-enable", pluginName), o.BatchConfig.ThrottleEnable, "是否启用批量限流.仅用于批处理模式.")
	fs.Float32Var(&o.BatchConfig.ThrottleQPS, fmt.Sprintf("audit-%s-batch-throttle-qps", pluginName), o.BatchConfig.ThrottleQPS, "每秒最大平均批次数.仅用于批处理模式.")
	fs.IntVar(&o.BatchConfig.ThrottleBurst, fmt.Sprintf("audit-%s-batch-throttle-burst", pluginName), o.BatchConfig.ThrottleBurst, "如果之前没有使用ThrottleQPS,则同一时刻发送的最大请求数.仅用于批处理模式.")
}

type ignoreErrorsBackend struct {
	audit.Backend
}

func (i *ignoreErrorsBackend) ProcessEvents(ev ...*auditinternal.Event) bool {
	i.Backend.ProcessEvents(ev...)
	return true
}

func (i *ignoreErrorsBackend) String() string {
	return fmt.Sprintf("ignoreErrors<%s>", i.Backend)
}

func (o *AuditBatchOptions) wrapBackend(delegate audit.Backend) audit.Backend {
	if o.Mode == ModeBlockingStrict {
		return delegate
	}
	if o.Mode == ModeBlocking {
		return &ignoreErrorsBackend{Backend: delegate}
	}
	return pluginbuffered.NewBackend(delegate, o.BatchConfig)
}

func (o *AuditTruncateOptions) Validate(pluginName string) error {
	config := o.TruncateConfig
	if config.MaxEventSize <= 0 {
		return fmt.Errorf("invalid audit truncate %s max event size %v, must be a positive number", pluginName, config.MaxEventSize)
	}
	if config.MaxBatchSize < config.MaxEventSize {
		return fmt.Errorf("invalid audit truncate %s max batch size %v, must be greater than "+
			"max event size (%v)", pluginName, config.MaxBatchSize, config.MaxEventSize)
	}
	return nil
}

func (o *AuditTruncateOptions) AddFlags(pluginName string, fs *pflag.FlagSet) {
	fs.BoolVar(&o.Enabled, fmt.Sprintf("audit-%s-truncate-enabled", pluginName), o.Enabled, "是否启用事件和批量截断功能.")
	fs.Int64Var(&o.TruncateConfig.MaxBatchSize, fmt.Sprintf("audit-%s-truncate-max-batch-size", pluginName), o.TruncateConfig.MaxBatchSize, "发送到底层后台的批次的最大尺寸.实际序列化的大小可以多出几百字节.如果一个批次超过了这个限制,它就会被分成几个尺寸较小的批次.")
	fs.Int64Var(&o.TruncateConfig.MaxEventSize, fmt.Sprintf("audit-%s-truncate-max-event-size", pluginName), o.TruncateConfig.MaxEventSize, "发送给底层后端的审计事件的最大尺寸.如果一个事件的大小大于这个数字,第一个请求和响应就会被删除,如果这还不能减少足够的大小,事件就会被丢弃.")
}

func (o *AuditTruncateOptions) wrapBackend(delegate audit.Backend, gv schema.GroupVersion) audit.Backend {
	if !o.Enabled {
		return delegate // 委托
	}
	return plugintruncate.NewBackend(delegate, o.TruncateConfig, gv)
}

func (o *AuditLogOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.Path, "audit-log-path", o.Path, "如果设置了,所有到达apiserver的请求都将被记录到这个文件中.'-'表示标准输出.")
	fs.IntVar(&o.MaxAge, "audit-log-maxage", o.MaxAge, "根据文件名中编码的时间戳保留旧审计日志文件的最大天数.")
	fs.IntVar(&o.MaxBackups, "audit-log-maxbackup", o.MaxBackups, "保留旧审计日志文件的最大数量.将值设置为0意味着对文件数量没有限制.")
	fs.IntVar(&o.MaxSize, "audit-log-maxsize", o.MaxSize, "审计日志文件旋转之前的最大大小(以兆字节为单位).")
	fs.StringVar(&o.Format, "audit-log-format", o.Format, "审计日志的格式. legacy:为每个事件指定一行文本格式. json:表示结构化json格式 . "+strings.Join(pluginlog.AllowedFormats, ",")+".")
	fs.StringVar(&o.GroupVersionString, "audit-log-version", o.GroupVersionString, "用于序列化写入日志的审计事件的API组和版本")
	fs.BoolVar(&o.Compress, "audit-log-compress", o.Compress, "如果设置,旋转的日志文件将使用gzip压缩.")
}

func (o *AuditLogOptions) Validate() []error {
	//根据选项检查日志后端是否开启.
	if !o.enabled() {
		return nil
	}

	var allErrors []error

	if err := validateBackendBatchOptions(pluginlog.PluginName, o.BatchOptions); err != nil {
		allErrors = append(allErrors, err)
	}
	if err := o.TruncateOptions.Validate(pluginlog.PluginName); err != nil {
		allErrors = append(allErrors, err)
	}

	if err := validateGroupVersionString(o.GroupVersionString); err != nil {
		allErrors = append(allErrors, err)
	}

	// Check log format
	if !sets.NewString(pluginlog.AllowedFormats...).Has(o.Format) {
		allErrors = append(allErrors, fmt.Errorf("invalid audit log format %s, allowed formats are %q", o.Format, strings.Join(pluginlog.AllowedFormats, ",")))
	}

	// Check validities of MaxAge, MaxBackups and MaxSize of log options, if file log backend is enabled.
	if o.MaxAge < 0 {
		allErrors = append(allErrors, fmt.Errorf("--audit-log-maxage %v can't be a negative number", o.MaxAge))
	}
	if o.MaxBackups < 0 {
		allErrors = append(allErrors, fmt.Errorf("--audit-log-maxbackup %v can't be a negative number", o.MaxBackups))
	}
	if o.MaxSize < 0 {
		allErrors = append(allErrors, fmt.Errorf("--audit-log-maxsize %v can't be a negative number", o.MaxSize))
	}

	return allErrors
}

func (o *AuditLogOptions) enabled() bool {
	return o != nil && o.Path != ""
}

func (o *AuditLogOptions) getWriter() (io.Writer, error) {
	if !o.enabled() {
		return nil, nil
	}

	if o.Path == "-" {
		return os.Stdout, nil
	}

	if err := o.ensureLogFile(); err != nil {
		return nil, fmt.Errorf("ensureLogFile: %w", err)
	}

	return &lumberjack.Logger{
		Filename:   o.Path,
		MaxAge:     o.MaxAge,
		MaxBackups: o.MaxBackups,
		MaxSize:    o.MaxSize,
		Compress:   o.Compress,
	}, nil
}

func (o *AuditLogOptions) ensureLogFile() error {
	if err := os.MkdirAll(filepath.Dir(o.Path), 0700); err != nil {
		return err
	}
	mode := os.FileMode(0600)
	f, err := os.OpenFile(o.Path, os.O_CREATE|os.O_APPEND|os.O_RDWR, mode)
	if err != nil {
		return err
	}
	return f.Close()
}

func (o *AuditLogOptions) newBackend(w io.Writer) audit.Backend {
	groupVersion, _ := schema.ParseGroupVersion(o.GroupVersionString)
	log := pluginlog.NewBackend(w, o.Format, groupVersion)
	log = o.BatchOptions.wrapBackend(log)
	log = o.TruncateOptions.wrapBackend(log, groupVersion)
	return log
}

func (o *AuditWebhookOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.ConfigFile, "audit-webhook-config-file", o.ConfigFile, "定义审计webhook配置的kubeconfig格式文件的路径.")
	fs.DurationVar(&o.InitialBackoff, "audit-webhook-initial-backoff", o.InitialBackoff, "在重试第一个失败的请求之前要等待的时间.")
	fs.DurationVar(&o.InitialBackoff, "audit-webhook-batch-initial-backoff", o.InitialBackoff, "在重试第一个失败的请求之前要等待的时间.")
	fs.MarkDeprecated("audit-webhook-batch-initial-backoff", "已废弃,请使用 --audit-webhook-initial-backoff 来代替.")
	fs.StringVar(&o.GroupVersionString, "audit-webhook-version", o.GroupVersionString, "用于序列化写入webhook的审计事件的API组和版本.")
}

func (o *AuditWebhookOptions) Validate() []error {
	if !o.enabled() {
		return nil
	}

	var allErrors []error
	if err := validateBackendBatchOptions(pluginwebhook.PluginName, o.BatchOptions); err != nil {
		allErrors = append(allErrors, err)
	}
	if err := o.TruncateOptions.Validate(pluginwebhook.PluginName); err != nil {
		allErrors = append(allErrors, err)
	}

	if err := validateGroupVersionString(o.GroupVersionString); err != nil {
		allErrors = append(allErrors, err)
	}
	return allErrors
}

func (o *AuditWebhookOptions) enabled() bool {
	return o != nil && o.ConfigFile != ""
}

// newUntruncatedBackend returns a webhook backend without the truncate options applied
// this is done so that the same trucate backend can wrap both the webhook and dynamic backends
func (o *AuditWebhookOptions) newUntruncatedBackend(customDial utilnet.DialFunc) (audit.Backend, error) {
	groupVersion, _ := schema.ParseGroupVersion(o.GroupVersionString)
	webhook, err := pluginwebhook.NewBackend(o.ConfigFile, groupVersion, webhook.DefaultRetryBackoffWithInitialDelay(o.InitialBackoff), customDial)
	if err != nil {
		return nil, fmt.Errorf("initializing audit webhook: %v", err)
	}
	webhook = o.BatchOptions.wrapBackend(webhook)
	return webhook, nil
}

// defaultWebhookBatchConfig returns the default BatchConfig used by the Webhook backend.
func defaultWebhookBatchConfig() pluginbuffered.BatchConfig {
	return pluginbuffered.BatchConfig{
		BufferSize:   defaultBatchBufferSize,
		MaxBatchSize: defaultBatchMaxSize,
		MaxBatchWait: defaultBatchMaxWait,

		ThrottleEnable: true,
		ThrottleQPS:    defaultBatchThrottleQPS,
		ThrottleBurst:  defaultBatchThrottleBurst,

		AsyncDelegate: true,
	}
}

// defaultLogBatchConfig returns the default BatchConfig used by the Log backend.
func defaultLogBatchConfig() pluginbuffered.BatchConfig {
	return pluginbuffered.BatchConfig{
		BufferSize:     defaultBatchBufferSize,
		MaxBatchSize:   1, // 批处理对于日志文件无效
		ThrottleEnable: false,
		AsyncDelegate:  false, // 异步日志线程只是创建锁争用.
	}
}
