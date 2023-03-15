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
	// Policy configuration file for filtering audit events that are captured.
	// If unspecified, a default is provided.
	PolicyFile string

	// Plugin options
	LogOptions     AuditLogOptions
	WebhookOptions AuditWebhookOptions
}

const (
	// ModeBatch indicates that the audit backend should buffer audit events
	// internally, sending batch updates either once a certain number of
	// events have been received or a certain amount of time has passed.
	ModeBatch = "batch"
	// ModeBlocking causes the audit backend to block on every attempt to process
	// a set of events. This causes requests to the API server to wait for the
	// flush before sending a response.
	ModeBlocking = "blocking"
	// ModeBlockingStrict is the same as ModeBlocking, except when there is
	// a failure during audit logging at RequestReceived stage, the whole
	// request to apiserver will fail.
	ModeBlockingStrict = "blocking-strict"
)

// AllowedModes is the modes known for audit backends.
var AllowedModes = []string{
	ModeBatch,
	ModeBlocking,
	ModeBlockingStrict,
}

type AuditBatchOptions struct {
	// Should the backend asynchronous batch events to the webhook backend or
	// should the backend block responses?
	//
	// Defaults to asynchronous batch events.
	Mode string
	// Configuration for batching backend. Only used in batch mode.
	BatchConfig pluginbuffered.BatchConfig
}

type AuditTruncateOptions struct {
	// Whether truncating is enabled or not.
	Enabled bool

	// Truncating configuration.
	TruncateConfig plugintruncate.Config
}

// AuditLogOptions determines the output of the structured audit log by default.
type AuditLogOptions struct {
	Path       string
	MaxAge     int
	MaxBackups int
	MaxSize    int
	Format     string
	Compress   bool

	BatchOptions    AuditBatchOptions
	TruncateOptions AuditTruncateOptions

	// API group version used for serializing audit events.
	GroupVersionString string
}

// AuditWebhookOptions control the webhook configuration for audit events.
type AuditWebhookOptions struct {
	ConfigFile     string
	InitialBackoff time.Duration

	BatchOptions    AuditBatchOptions
	TruncateOptions AuditTruncateOptions

	// API group version used for serializing audit events.
	GroupVersionString string
}

// AuditDynamicOptions control the configuration of dynamic backends for audit events
type AuditDynamicOptions struct {
	// Enabled tells whether the dynamic audit capability is enabled.
	Enabled bool

	// Configuration for batching backend. This is currently only used as an override
	// for integration tests
	BatchConfig *pluginbuffered.BatchConfig
}

func NewAuditOptions() *AuditOptions {
	return &AuditOptions{
		WebhookOptions: AuditWebhookOptions{
			InitialBackoff: pluginwebhook.DefaultInitialBackoffDelay,
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

	fs.StringVar(&o.PolicyFile, "audit-policy-file", o.PolicyFile,
		"Path to the file that defines the audit policy configuration.")

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

	// 1. Build policy evaluator
	evaluator, err := o.newPolicyRuleEvaluator()
	if err != nil {
		return err
	}

	// 2. Build log backend
	var logBackend audit.Backend
	w, err := o.LogOptions.getWriter()
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

	groupVersion, err := schema.ParseGroupVersion(o.WebhookOptions.GroupVersionString)
	if err != nil {
		return err
	}

	// 4. Apply dynamic options.
	var dynamicBackend audit.Backend
	if webhookBackend != nil {
		// if only webhook is enabled wrap it in the truncate options
		dynamicBackend = o.WebhookOptions.TruncateOptions.wrapBackend(webhookBackend, groupVersion)
	}

	// 5. Set the policy rule evaluator
	c.AuditPolicyRuleEvaluator = evaluator

	// 6. Join the log backend with the webhooks
	c.AuditBackend = appendBackend(logBackend, dynamicBackend)

	if c.AuditBackend != nil {
		klog.V(2).Infof("Using audit backend: %s", c.AuditBackend)
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
	fs.StringVar(&o.Mode, fmt.Sprintf("audit-%s-mode", pluginName), o.Mode,
		"Strategy for sending audit events. Blocking indicates sending events should block"+
			" server responses. Batch causes the backend to buffer and write events"+
			" asynchronously. Known modes are "+strings.Join(AllowedModes, ",")+".")
	fs.IntVar(&o.BatchConfig.BufferSize, fmt.Sprintf("audit-%s-batch-buffer-size", pluginName),
		o.BatchConfig.BufferSize, "The size of the buffer to store events before "+
			"batching and writing. Only used in batch mode.")
	fs.IntVar(&o.BatchConfig.MaxBatchSize, fmt.Sprintf("audit-%s-batch-max-size", pluginName),
		o.BatchConfig.MaxBatchSize, "The maximum size of a batch. Only used in batch mode.")
	fs.DurationVar(&o.BatchConfig.MaxBatchWait, fmt.Sprintf("audit-%s-batch-max-wait", pluginName),
		o.BatchConfig.MaxBatchWait, "The amount of time to wait before force writing the "+
			"batch that hadn't reached the max size. Only used in batch mode.")
	fs.BoolVar(&o.BatchConfig.ThrottleEnable, fmt.Sprintf("audit-%s-batch-throttle-enable", pluginName),
		o.BatchConfig.ThrottleEnable, "Whether batching throttling is enabled. Only used in batch mode.")
	fs.Float32Var(&o.BatchConfig.ThrottleQPS, fmt.Sprintf("audit-%s-batch-throttle-qps", pluginName),
		o.BatchConfig.ThrottleQPS, "Maximum average number of batches per second. "+
			"Only used in batch mode.")
	fs.IntVar(&o.BatchConfig.ThrottleBurst, fmt.Sprintf("audit-%s-batch-throttle-burst", pluginName),
		o.BatchConfig.ThrottleBurst, "Maximum number of requests sent at the same "+
			"moment if ThrottleQPS was not utilized before. Only used in batch mode.")
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
	fs.BoolVar(&o.Enabled, fmt.Sprintf("audit-%s-truncate-enabled", pluginName),
		o.Enabled, "Whether event and batch truncating is enabled.")
	fs.Int64Var(&o.TruncateConfig.MaxBatchSize, fmt.Sprintf("audit-%s-truncate-max-batch-size", pluginName),
		o.TruncateConfig.MaxBatchSize, "Maximum size of the batch sent to the underlying backend. "+
			"Actual serialized size can be several hundreds of bytes greater. If a batch exceeds this limit, "+
			"it is split into several batches of smaller size.")
	fs.Int64Var(&o.TruncateConfig.MaxEventSize, fmt.Sprintf("audit-%s-truncate-max-event-size", pluginName),
		o.TruncateConfig.MaxEventSize, "Maximum size of the audit event sent to the underlying backend. "+
			"If the size of an event is greater than this number, first request and response are removed, and "+
			"if this doesn't reduce the size enough, event is discarded.")
}

func (o *AuditTruncateOptions) wrapBackend(delegate audit.Backend, gv schema.GroupVersion) audit.Backend {
	if !o.Enabled {
		return delegate
	}
	return plugintruncate.NewBackend(delegate, o.TruncateConfig, gv)
}

func (o *AuditLogOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.Path, "audit-log-path", o.Path, "如果设置了，所有到达apiserver的请求都将被记录到这个文件中。'-'表示标准输出。")
	fs.IntVar(&o.MaxAge, "audit-log-maxage", o.MaxAge, "根据文件名中编码的时间戳保留旧审计日志文件的最大天数。")
	fs.IntVar(&o.MaxBackups, "audit-log-maxbackup", o.MaxBackups, "保留旧审计日志文件的最大数量。将值设置为0意味着对文件数量没有限制。")
	fs.IntVar(&o.MaxSize, "audit-log-maxsize", o.MaxSize, "审计日志文件旋转之前的最大大小(以兆字节为单位)。")
	fs.StringVar(&o.Format, "audit-log-format", o.Format,
		"审计日志的格式. legacy:为每个事件指定一行文本格式。 json:表示结构化json格式 . "+strings.Join(pluginlog.AllowedFormats, ",")+".")
	fs.StringVar(&o.GroupVersionString, "audit-log-version", o.GroupVersionString, "用于序列化写入日志的审计事件的API组和版本")
	fs.BoolVar(&o.Compress, "audit-log-compress", o.Compress, "如果设置，旋转的日志文件将使用gzip压缩。")
}

func (o *AuditLogOptions) Validate() []error {
	//根据选项检查日志后端是否开启。
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
	fs.StringVar(&o.ConfigFile, "audit-webhook-config-file", o.ConfigFile,
		"Path to a kubeconfig formatted file that defines the audit webhook configuration.")
	fs.DurationVar(&o.InitialBackoff, "audit-webhook-initial-backoff",
		o.InitialBackoff, "The amount of time to wait before retrying the first failed request.")
	fs.DurationVar(&o.InitialBackoff, "audit-webhook-batch-initial-backoff",
		o.InitialBackoff, "The amount of time to wait before retrying the first failed request.")
	fs.MarkDeprecated("audit-webhook-batch-initial-backoff",
		"Deprecated, use --audit-webhook-initial-backoff instead.")
	fs.StringVar(&o.GroupVersionString, "audit-webhook-version", o.GroupVersionString,
		"API group and version used for serializing audit events written to webhook.")
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
		BufferSize: defaultBatchBufferSize,
		// Batching is not useful for the log-file backend.
		// MaxBatchWait ignored.
		MaxBatchSize:   1,
		ThrottleEnable: false,
		// Asynchronous log threads just create lock contention.
		AsyncDelegate: false,
	}
}
