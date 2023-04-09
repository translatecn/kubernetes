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
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/pflag"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/egressselector"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/klog/v2"
	openapicommon "k8s.io/kube-openapi/pkg/common"
	serviceaccountcontroller "k8s.io/kubernetes/pkg/controller/serviceaccount"
	kubeauthenticator "k8s.io/kubernetes/pkg/kubeapiserver/authenticator"
	authzmodes "k8s.io/kubernetes/pkg/kubeapiserver/authorizer/modes"
	"k8s.io/kubernetes/plugin/pkg/auth/authenticator/token/bootstrap"
)

// BuiltInAuthenticationOptions 包含API服务器的所有内置身份验证选项
type BuiltInAuthenticationOptions struct {
	APIAudiences         []string                                           // 预先规定的调用者们
	Anonymous            *AnonymousAuthenticationOptions                    // 匿名授权
	BootstrapToken       *BootstrapTokenAuthenticationOptions               //
	ClientCert           *genericoptions.ClientCertAuthenticationOptions    //
	OIDC                 *OIDCAuthenticationOptions                         // https://www.jianshu.com/p/fb4a386ef718
	RequestHeader        *genericoptions.RequestHeaderAuthenticationOptions //
	ServiceAccounts      *ServiceAccountAuthenticationOptions               //
	TokenFile            *TokenFileAuthenticationOptions                    //
	WebHook              *WebHookAuthenticationOptions                      //
	TokenSuccessCacheTTL time.Duration                                      //
	TokenFailureCacheTTL time.Duration                                      //
}

// AnonymousAuthenticationOptions contains anonymous authentication options for API Server
type AnonymousAuthenticationOptions struct {
	Allow bool // 是否允许匿名访问
}

// BootstrapTokenAuthenticationOptions 包含API服务器的引导令牌身份验证选项
type BootstrapTokenAuthenticationOptions struct {
	Enable bool
}

// OIDCAuthenticationOptions contains OIDC authentication options for API Server
type OIDCAuthenticationOptions struct {
	CAFile         string
	ClientID       string
	IssuerURL      string
	UsernameClaim  string
	UsernamePrefix string
	GroupsClaim    string
	GroupsPrefix   string
	SigningAlgs    []string
	RequiredClaims map[string]string
}

// ServiceAccountAuthenticationOptions 包含API服务器的服务账户认证选项
type ServiceAccountAuthenticationOptions struct {
	KeyFiles         []string // --service-account-key-file
	Lookup           bool     // 如果为真，则验证etcd中存在的ServiceAccount令牌作为身份验证的一部分。
	Issuers          []string // 其全称为 “Issuer Identifier”,中文意思就是：颁发者身份标识,表示 Token 颁发者的唯一标识,一般是一个 http(s) url,如 https://www.baidu.com
	JWKSURI          string
	MaxExpiration    time.Duration
	ExtendExpiration bool
}

// TokenFileAuthenticationOptions  包含API服务器的令牌文件认证选项
type TokenFileAuthenticationOptions struct {
	TokenFile string
}

// WebHookAuthenticationOptions 包含API服务器的web钩子身份验证选项
type WebHookAuthenticationOptions struct {
	ConfigFile   string        //
	Version      string        //
	CacheTTL     time.Duration //
	RetryBackoff *wait.Backoff // 认证webhook重试逻辑的回退参数
}

// NewBuiltInAuthenticationOptions create a new BuiltInAuthenticationOptions, just set default token cache TTL
func NewBuiltInAuthenticationOptions() *BuiltInAuthenticationOptions {
	return &BuiltInAuthenticationOptions{
		TokenSuccessCacheTTL: 10 * time.Second,
		TokenFailureCacheTTL: 0 * time.Second,
	}
}

// WithAll set default value for every build-in authentication option
func (o *BuiltInAuthenticationOptions) WithAll() *BuiltInAuthenticationOptions {
	return o.
		WithAnonymous().
		WithBootstrapToken().
		WithClientCert().
		WithOIDC().
		WithRequestHeader().
		WithServiceAccounts().
		WithTokenFile().
		WithWebHook()
}

// WithAnonymous 设置匿名认证的缺省值
func (o *BuiltInAuthenticationOptions) WithAnonymous() *BuiltInAuthenticationOptions {
	o.Anonymous = &AnonymousAuthenticationOptions{Allow: true}
	return o
}

// WithBootstrapToken set default value for bootstrap token authentication
func (o *BuiltInAuthenticationOptions) WithBootstrapToken() *BuiltInAuthenticationOptions {
	o.BootstrapToken = &BootstrapTokenAuthenticationOptions{}
	return o
}

// WithClientCert set default value for client cert
func (o *BuiltInAuthenticationOptions) WithClientCert() *BuiltInAuthenticationOptions {
	o.ClientCert = &genericoptions.ClientCertAuthenticationOptions{}
	return o
}

// WithOIDC set default value for OIDC authentication
func (o *BuiltInAuthenticationOptions) WithOIDC() *BuiltInAuthenticationOptions {
	o.OIDC = &OIDCAuthenticationOptions{}
	return o
}

// WithRequestHeader set default value for request header authentication
func (o *BuiltInAuthenticationOptions) WithRequestHeader() *BuiltInAuthenticationOptions {
	o.RequestHeader = &genericoptions.RequestHeaderAuthenticationOptions{}
	return o
}

// WithServiceAccounts 设置服务帐户认证的默认值
func (o *BuiltInAuthenticationOptions) WithServiceAccounts() *BuiltInAuthenticationOptions {
	o.ServiceAccounts = &ServiceAccountAuthenticationOptions{Lookup: true, ExtendExpiration: true}
	return o
}

// WithTokenFile set default value for token file authentication
func (o *BuiltInAuthenticationOptions) WithTokenFile() *BuiltInAuthenticationOptions {
	o.TokenFile = &TokenFileAuthenticationOptions{}
	return o
}

// WithWebHook set default value for web hook authentication
func (o *BuiltInAuthenticationOptions) WithWebHook() *BuiltInAuthenticationOptions {
	o.WebHook = &WebHookAuthenticationOptions{
		Version:      "v1beta1",
		CacheTTL:     2 * time.Minute,
		RetryBackoff: genericoptions.DefaultAuthWebhookRetryBackoff(),
	}
	return o
}

// Validate checks invalid config combination
func (o *BuiltInAuthenticationOptions) Validate() []error {
	var allErrors []error

	if o.OIDC != nil && (len(o.OIDC.IssuerURL) > 0) != (len(o.OIDC.ClientID) > 0) {
		allErrors = append(allErrors, fmt.Errorf("oidc-issuer-url and oidc-client-id should be specified together"))
	}

	if o.ServiceAccounts != nil && len(o.ServiceAccounts.Issuers) > 0 {
		seen := make(map[string]bool)
		for _, issuer := range o.ServiceAccounts.Issuers {
			if strings.Contains(issuer, ":") {
				if _, err := url.Parse(issuer); err != nil {
					allErrors = append(allErrors, fmt.Errorf("service-account-issuer %q contained a ':' but was not a valid URL: %v", issuer, err))
					continue
				}
			}
			if issuer == "" {
				allErrors = append(allErrors, fmt.Errorf("service-account-issuer should not be an empty string"))
				continue
			}
			if seen[issuer] {
				allErrors = append(allErrors, fmt.Errorf("service-account-issuer %q is already specified", issuer))
				continue
			}
			seen[issuer] = true
		}
	}

	if o.ServiceAccounts != nil {
		if len(o.ServiceAccounts.Issuers) == 0 {
			allErrors = append(allErrors, errors.New("service-account-issuer is a required flag"))
		}
		if len(o.ServiceAccounts.KeyFiles) == 0 {
			allErrors = append(allErrors, errors.New("service-account-key-file is a required flag"))
		}

		// Validate the JWKS URI when it is explicitly set.
		// When unset, it is later derived from ExternalHost.
		if o.ServiceAccounts.JWKSURI != "" {
			if u, err := url.Parse(o.ServiceAccounts.JWKSURI); err != nil {
				allErrors = append(allErrors, fmt.Errorf("service-account-jwks-uri must be a valid URL: %v", err))
			} else if u.Scheme != "https" {
				allErrors = append(allErrors, fmt.Errorf("service-account-jwks-uri requires https scheme, parsed as: %v", u.String()))
			}
		}
	}

	if o.WebHook != nil {
		retryBackoff := o.WebHook.RetryBackoff
		if retryBackoff != nil && retryBackoff.Steps <= 0 {
			allErrors = append(allErrors, fmt.Errorf("number of webhook retry attempts must be greater than 0, but is: %d", retryBackoff.Steps))
		}
	}

	return allErrors
}

// AddFlags returns flags of authentication for a API Server
func (o *BuiltInAuthenticationOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringSliceVar(&o.APIAudiences, "api-audiences", o.APIAudiences,
		"API的标识符. sa令牌验证器将验证针对API使用的令牌是否绑定到这些使用者的至少一个.如果配置了 --service-account-issuer 标志而没有配置该标志,则该字段默认为包含发行者URL的单个元素列表.",
	)

	if o.Anonymous != nil {
		fs.BoolVar(&o.Anonymous.Allow, "anonymous-auth", o.Anonymous.Allow, "启用匿名请求到API服务器的安全端口。未被其他身份验证方法拒绝的请求被视为匿名请求。匿名请求的用户名为system: Anonymous，组名为system:unauthenticated。")
	}

	if o.BootstrapToken != nil {
		fs.BoolVar(&o.BootstrapToken.Enable, "enable-bootstrap-token-auth", o.BootstrapToken.Enable, "启用允许'bootstrap.kubernetes类型的secret io/token'在'kube-system'命名空间中用于TLS引导身份验证。")
	}

	if o.ClientCert != nil {
		o.ClientCert.AddFlags(fs)
	}

	if o.OIDC != nil {
		// 如果设置了，OpenID服务器的证书将由oidc- CA文件中的一个权威机构进行验证，否则将使用主机的根CA集。
		// https://www.jianshu.com/p/cb50363a47be
		fs.StringVar(&o.OIDC.IssuerURL, "oidc-issuer-url", o.OIDC.IssuerURL, "OpenID颁发者的URL，只接受HTTPS方案。如果设置了，它将用于验证OIDC JSON Web令牌(JWT)。")
		fs.StringVar(&o.OIDC.ClientID, "oidc-client-id", o.OIDC.ClientID, "如果设置了oidc-issuer-url，则必须设置OpenID Connect客户端的客户端ID。")
		fs.StringVar(&o.OIDC.CAFile, "oidc-ca-file", o.OIDC.CAFile, "如果设置了，OpenID服务器的证书将由 oidc-ca-file 中的一个权威机构进行验证，否则将使用主机的根CA集。")
		fs.StringVar(&o.OIDC.UsernameClaim, "oidc-username-claim", "sub", "OpenID声明用作用户名。注意，除了默认值('sub')之外的声明并不保证是唯一的和不可变的。")
		fs.StringVar(&o.OIDC.UsernamePrefix, "oidc-username-prefix", "", "如果提供，所有用户名都将以该值作为前缀。")
		fs.StringVar(&o.OIDC.GroupsClaim, "oidc-groups-claim", "", "如果提供，则指定用户组的自定义OpenID Connect声明的名称。")
		fs.StringVar(&o.OIDC.GroupsPrefix, "oidc-groups-prefix", "", "如果提供，所有组都将以该值作为前缀，以防止与其他身份验证策略冲突。")
		fs.StringSliceVar(&o.OIDC.SigningAlgs, "oidc-signing-algs", []string{"RS256"}, "允许的JOSE非对称签名算法的逗号分隔列表。")
		fs.Var(cliflag.NewMapStringStringNoSplit(&o.OIDC.RequiredClaims), "oidc-required-claim", "在ID令牌中描述必需声明的键=值对。如果设置了，则验证该声明是否存在于具有匹配值的ID令牌中。可指定多个声明。")
	}

	if o.RequestHeader != nil {
		o.RequestHeader.AddFlags(fs)
	}

	if o.ServiceAccounts != nil {
		fs.StringArrayVar(&o.ServiceAccounts.KeyFiles, "service-account-key-file", o.ServiceAccounts.KeyFiles,
			"包含pem编码的x509 RSA或ECDSA私钥或公钥的文件，用于验证ServiceAccount令牌。"+
				"指定的文件可以包含多个键，并且该标志可以在不同的文件中指定多次。如果未指定，则使用--tls-private-key-file。提供--service-account-signing-key-file时必须指定")

		fs.BoolVar(&o.ServiceAccounts.Lookup, "service-account-lookup", o.ServiceAccounts.Lookup, "如果为真，则验证etcd中存在的ServiceAccount令牌作为身份验证的一部分。")

		fs.StringArrayVar(&o.ServiceAccounts.Issuers, "service-account-issuer", o.ServiceAccounts.Issuers, "服务帐户令牌发行者的标识符.发行者将在已发行令牌的\"iss\"声明中声明此标识符.")

		fs.StringVar(&o.ServiceAccounts.JWKSURI, "service-account-jwks-uri", o.ServiceAccounts.JWKSURI,
			"覆盖在/.famous/openid-configuration swagger文档中JSON Web Key Set的URI。"+
				"如果发现文档和密钥集是从API服务器的外部URL(自动检测或用外部主机名覆盖)以外的URL提供给依赖方，则此标志很有用。")

		fs.DurationVar(&o.ServiceAccounts.MaxExpiration, "service-account-max-token-expiration", o.ServiceAccounts.MaxExpiration,
			"由服务帐户令牌颁发者创建的令牌的最大有效期.如果请求的TokenRequest有效时间大于此值,则将发出具有此值有效时间的令牌")

		fs.BoolVar(&o.ServiceAccounts.ExtendExpiration, "service-account-extend-token-expiration", o.ServiceAccounts.ExtendExpiration,
			"在令牌生成过程中打开预计的服务帐户过期扩展,这有助于从遗留令牌安全过渡到绑定服务帐户令牌功能."+
				"如果启用了该标志,则允许注入的令牌将被延长至1年,以防止转换期间出现意外故障,忽略 service-account-max-token-expiration 的值.")
	}

	if o.TokenFile != nil {
		fs.StringVar(&o.TokenFile.TokenFile, "token-auth-file", o.TokenFile.TokenFile, "如果设置了，将用于通过令牌身份验证保护API服务器安全端口的文件。")
	}

	if o.WebHook != nil {
		fs.StringVar(&o.WebHook.ConfigFile, "authentication-token-webhook-config-file", o.WebHook.ConfigFile, "kube config格式的token认证webhook配置文件。API服务器将查询远程服务以确定承载令牌的身份验证。")
		fs.StringVar(&o.WebHook.Version, "authentication-token-webhook-version", o.WebHook.Version, "authentication.k8s的API版本。io TokenReview发送到webhook和期望收到的。")
		fs.DurationVar(&o.WebHook.CacheTTL, "authentication-token-webhook-cache-ttl", o.WebHook.CacheTTL, "缓存webhook令牌验证器响应的持续时间。")
	}
}

// ToAuthenticationConfig ✅ convert BuiltInAuthenticationOptions to kubeauthenticator.Config
func (o *BuiltInAuthenticationOptions) ToAuthenticationConfig() (kubeauthenticator.Config, error) {
	ret := kubeauthenticator.Config{
		TokenSuccessCacheTTL: o.TokenSuccessCacheTTL,
		TokenFailureCacheTTL: o.TokenFailureCacheTTL,
	}

	if o.Anonymous != nil {
		ret.Anonymous = o.Anonymous.Allow
	}

	if o.BootstrapToken != nil {
		ret.BootstrapToken = o.BootstrapToken.Enable
	}

	if o.ClientCert != nil {
		var err error
		ret.ClientCAContentProvider, err = o.ClientCert.GetClientCAContentProvider()
		if err != nil {
			return kubeauthenticator.Config{}, err
		}
	}

	if o.OIDC != nil {
		ret.OIDCCAFile = o.OIDC.CAFile
		ret.OIDCClientID = o.OIDC.ClientID
		ret.OIDCGroupsClaim = o.OIDC.GroupsClaim
		ret.OIDCGroupsPrefix = o.OIDC.GroupsPrefix
		ret.OIDCIssuerURL = o.OIDC.IssuerURL
		ret.OIDCUsernameClaim = o.OIDC.UsernameClaim
		ret.OIDCUsernamePrefix = o.OIDC.UsernamePrefix
		ret.OIDCSigningAlgs = o.OIDC.SigningAlgs
		ret.OIDCRequiredClaims = o.OIDC.RequiredClaims
	}

	if o.RequestHeader != nil {
		var err error
		ret.RequestHeaderConfig, err = o.RequestHeader.ToAuthenticationRequestHeaderConfig()
		if err != nil {
			return kubeauthenticator.Config{}, err
		}
	}

	ret.APIAudiences = o.APIAudiences // 预先规定的调用者们
	if o.ServiceAccounts != nil {     // --service-account-key-file
		if len(o.ServiceAccounts.Issuers) != 0 && len(o.APIAudiences) == 0 {
			ret.APIAudiences = authenticator.Audiences(o.ServiceAccounts.Issuers)
		}
		ret.ServiceAccountKeyFiles = o.ServiceAccounts.KeyFiles
		ret.ServiceAccountIssuers = o.ServiceAccounts.Issuers
		ret.ServiceAccountLookup = o.ServiceAccounts.Lookup
	}

	if o.TokenFile != nil {
		ret.TokenAuthFile = o.TokenFile.TokenFile
	}

	if o.WebHook != nil {
		ret.WebhookTokenAuthnConfigFile = o.WebHook.ConfigFile
		ret.WebhookTokenAuthnVersion = o.WebHook.Version
		ret.WebhookTokenAuthnCacheTTL = o.WebHook.CacheTTL
		ret.WebhookRetryBackoff = o.WebHook.RetryBackoff

		if len(o.WebHook.ConfigFile) > 0 && o.WebHook.CacheTTL > 0 {
			if o.TokenSuccessCacheTTL > 0 && o.WebHook.CacheTTL < o.TokenSuccessCacheTTL {
				klog.Warningf("对于尝试验证成功的令牌身份，webhook缓存的TTL %s比缓存的总TTL %s短。", o.WebHook.CacheTTL, o.TokenSuccessCacheTTL)
			}
			if o.TokenFailureCacheTTL > 0 && o.WebHook.CacheTTL < o.TokenFailureCacheTTL {
				klog.Warningf("对于尝试验证失败的令牌身份，webhook缓存的TTL %s比缓存的总TTL %s短。", o.WebHook.CacheTTL, o.TokenFailureCacheTTL)
			}
		}
	}

	return ret, nil
}

// ApplyTo ✅
func (o *BuiltInAuthenticationOptions) ApplyTo(
	authInfo *genericapiserver.AuthenticationInfo,
	secureServing *genericapiserver.SecureServingInfo,
	egressSelector *egressselector.EgressSelector,
	openAPIConfig *openapicommon.Config,
	openAPIV3Config *openapicommon.Config,
	extclient kubernetes.Interface,
	versionedInformer informers.SharedInformerFactory) error {
	if o == nil {
		return nil
	}

	if openAPIConfig == nil {
		return errors.New("uninitialized OpenAPIConfig")
	}

	authenticatorConfig, err := o.ToAuthenticationConfig()
	if err != nil {
		return err
	}

	if authenticatorConfig.ClientCAContentProvider != nil {
		if err = authInfo.ApplyClientCert(authenticatorConfig.ClientCAContentProvider, secureServing); err != nil {
			return fmt.Errorf("unable to load client CA file: %v", err)
		}
	}
	if authenticatorConfig.RequestHeaderConfig != nil && authenticatorConfig.RequestHeaderConfig.CAContentProvider != nil {
		if err = authInfo.ApplyClientCert(authenticatorConfig.RequestHeaderConfig.CAContentProvider, secureServing); err != nil {
			return fmt.Errorf("unable to load client CA file: %v", err)
		}
	}

	authInfo.APIAudiences = o.APIAudiences
	if o.ServiceAccounts != nil && len(o.ServiceAccounts.Issuers) != 0 && len(o.APIAudiences) == 0 {
		authInfo.APIAudiences = authenticator.Audiences(o.ServiceAccounts.Issuers)
	}

	authenticatorConfig.ServiceAccountTokenGetter = serviceaccountcontroller.NewGetterFromClient(
		extclient,
		versionedInformer.Core().V1().Secrets().Lister(),
		versionedInformer.Core().V1().ServiceAccounts().Lister(),
		versionedInformer.Core().V1().Pods().Lister(),
	)
	authenticatorConfig.SecretsWriter = extclient.CoreV1()

	authenticatorConfig.BootstrapTokenAuthenticator = bootstrap.NewTokenAuthenticator(
		versionedInformer.Core().V1().Secrets().Lister().Secrets(metav1.NamespaceSystem),
	)

	if egressSelector != nil {
		egressDialer, err := egressSelector.Lookup(egressselector.ControlPlane.AsNetworkContext())
		if err != nil {
			return err
		}
		authenticatorConfig.CustomDial = egressDialer
	}

	authInfo.Authenticator, openAPIConfig.SecurityDefinitions, err = authenticatorConfig.New() // 认证集合创建
	if openAPIV3Config != nil {
		openAPIV3Config.SecurityDefinitions = openAPIConfig.SecurityDefinitions
	}
	if err != nil {
		return err
	}

	return nil
}

// ApplyAuthorization 修改是否允许匿名访问标志位
func (o *BuiltInAuthenticationOptions) ApplyAuthorization(authorization *BuiltInAuthorizationOptions) {
	if o == nil || authorization == nil || o.Anonymous == nil {
		return
	}

	// authorization ModeAlwaysAllow cannot be combined with AnonymousAuth.
	// in such a case the AnonymousAuth is stomped to false and you get a message
	if o.Anonymous.Allow && sets.NewString(authorization.Modes...).Has(authzmodes.ModeAlwaysAllow) {
		klog.Warningf("AlwaysAllow授权器不允许使用AnonymousAuth。将AnonymousAuth重置为false。您应该使用不同的授权程序")
		o.Anonymous.Allow = false
	}
}
