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
	"strings"
	"time"

	"github.com/spf13/pflag"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	versionedinformers "k8s.io/client-go/informers"
	"k8s.io/kubernetes/pkg/kubeapiserver/authorizer"
	authzmodes "k8s.io/kubernetes/pkg/kubeapiserver/authorizer/modes"
)

// BuiltInAuthorizationOptions contains all build-in authorization options for API Server
type BuiltInAuthorizationOptions struct {
	Modes                       []string // 授权模式
	PolicyFile                  string
	WebhookConfigFile           string
	WebhookVersion              string
	WebhookCacheAuthorizedTTL   time.Duration
	WebhookCacheUnauthorizedTTL time.Duration
	// WebhookRetryBackoff specifies the backoff parameters for the authorization webhook retry logic.
	// This allows us to configure the sleep time at each iteration and the maximum number of retries allowed
	// before we fail the webhook call in order to limit the fan out that ensues when the system is degraded.
	WebhookRetryBackoff *wait.Backoff
}

// NewBuiltInAuthorizationOptions 内置授权
func NewBuiltInAuthorizationOptions() *BuiltInAuthorizationOptions {
	return &BuiltInAuthorizationOptions{
		Modes:                       []string{authzmodes.ModeAlwaysAllow},
		WebhookVersion:              "v1beta1",
		WebhookCacheAuthorizedTTL:   5 * time.Minute,
		WebhookCacheUnauthorizedTTL: 30 * time.Second,
		WebhookRetryBackoff:         genericoptions.DefaultAuthWebhookRetryBackoff(),
	}
}

// Validate checks invalid config combination
func (o *BuiltInAuthorizationOptions) Validate() []error {
	if o == nil {
		return nil
	}
	var allErrors []error

	if len(o.Modes) == 0 {
		allErrors = append(allErrors, fmt.Errorf("at least one authorization-mode must be passed"))
	}

	modes := sets.NewString(o.Modes...)
	for _, mode := range o.Modes {
		if !authzmodes.IsValidAuthorizationMode(mode) {
			allErrors = append(allErrors, fmt.Errorf("authorization-mode %q is not a valid mode", mode))
		}
		if mode == authzmodes.ModeABAC && o.PolicyFile == "" {
			allErrors = append(allErrors, fmt.Errorf("authorization-mode ABAC's authorization policy file not passed"))
		}
		if mode == authzmodes.ModeWebhook && o.WebhookConfigFile == "" {
			allErrors = append(allErrors, fmt.Errorf("authorization-mode Webhook's authorization config file not passed"))
		}
	}

	if o.PolicyFile != "" && !modes.Has(authzmodes.ModeABAC) {
		allErrors = append(allErrors, fmt.Errorf("cannot specify --authorization-policy-file without mode ABAC"))
	}

	if o.WebhookConfigFile != "" && !modes.Has(authzmodes.ModeWebhook) {
		allErrors = append(allErrors, fmt.Errorf("cannot specify --authorization-webhook-config-file without mode Webhook"))
	}

	if len(o.Modes) != modes.Len() {
		allErrors = append(allErrors, fmt.Errorf("authorization-mode %q has mode specified more than once", o.Modes))
	}

	if o.WebhookRetryBackoff != nil && o.WebhookRetryBackoff.Steps <= 0 {
		allErrors = append(allErrors, fmt.Errorf("number of webhook retry attempts must be greater than 0, but is: %d", o.WebhookRetryBackoff.Steps))
	}

	return allErrors
}

// AddFlags returns flags of authorization for a API Server
func (o *BuiltInAuthorizationOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringSliceVar(&o.Modes, "authorization-mode", o.Modes, "在安全端口上进行授权的有序插件列表。逗号分隔列表: "+strings.Join(authzmodes.AuthorizationModeChoices, ",")+".")
	fs.StringVar(&o.PolicyFile, "authorization-policy-file", o.PolicyFile, "在安全端口上使用json逐行格式的授权策略文件，与--authorization-mode=ABAC一起使用。")
	fs.StringVar(&o.WebhookConfigFile, "authorization-webhook-config-file", o.WebhookConfigFile, "kubecconfig格式的webhook配置文件，使用--authorization-mode=webhook。API服务器将查询远程服务，以确定对API服务器的安全端口的访问。")
	fs.StringVar(&o.WebhookVersion, "authorization-webhook-version", o.WebhookVersion, "authorization.k8s的API版本。io.SubjectAccessReview发送到webhook和期望从webhook收到。")
	fs.DurationVar(&o.WebhookCacheAuthorizedTTL, "authorization-webhook-cache-authorized-ttl", o.WebhookCacheAuthorizedTTL, "缓存webhook授权者的“授权”响应的持续时间。")
	fs.DurationVar(&o.WebhookCacheUnauthorizedTTL, "authorization-webhook-cache-unauthorized-ttl", o.WebhookCacheUnauthorizedTTL, "缓存来自webhook授权者的“未授权”响应的持续时间。")
}

// ToAuthorizationConfig convert BuiltInAuthorizationOptions to authorizer.Config
func (o *BuiltInAuthorizationOptions) ToAuthorizationConfig(versionedInformerFactory versionedinformers.SharedInformerFactory) authorizer.Config {
	return authorizer.Config{
		AuthorizationModes:          o.Modes, // NODE,RBAC
		PolicyFile:                  o.PolicyFile,
		WebhookConfigFile:           o.WebhookConfigFile,
		WebhookVersion:              o.WebhookVersion,
		WebhookCacheAuthorizedTTL:   o.WebhookCacheAuthorizedTTL,
		WebhookCacheUnauthorizedTTL: o.WebhookCacheUnauthorizedTTL,
		VersionedInformerFactory:    versionedInformerFactory,
		WebhookRetryBackoff:         o.WebhookRetryBackoff,
	}
}
