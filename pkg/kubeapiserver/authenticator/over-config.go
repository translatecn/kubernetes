/*
Copyright 2014 The Kubernetes Authors.

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

package authenticator

import (
	"errors"
	"k8s.io/kubernetes/plugin/pkg/auth/authenticator/token/bootstrap"
	"time"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/authenticatorfactory"
	"k8s.io/apiserver/pkg/authentication/group"
	"k8s.io/apiserver/pkg/authentication/request/anonymous"
	"k8s.io/apiserver/pkg/authentication/request/bearertoken"
	"k8s.io/apiserver/pkg/authentication/request/headerrequest"
	"k8s.io/apiserver/pkg/authentication/request/union"
	"k8s.io/apiserver/pkg/authentication/request/websocket"
	"k8s.io/apiserver/pkg/authentication/request/x509"
	tokencache "k8s.io/apiserver/pkg/authentication/token/cache"
	"k8s.io/apiserver/pkg/authentication/token/tokenfile"
	tokenunion "k8s.io/apiserver/pkg/authentication/token/union"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	webhookutil "k8s.io/apiserver/pkg/util/webhook"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/webhook"
	typedv1core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/kube-openapi/pkg/validation/spec"

	// Initialize all known client auth plugins.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/kubernetes/pkg/serviceaccount"
)

// Config 包含关于如何向Kube API服务器验证请求的数据
type Config struct {
	Anonymous                 bool
	BootstrapToken            bool
	TokenAuthFile             string
	OIDCIssuerURL             string
	OIDCClientID              string
	OIDCCAFile                string
	OIDCUsernameClaim         string
	OIDCUsernamePrefix        string
	OIDCGroupsClaim           string
	OIDCGroupsPrefix          string
	OIDCSigningAlgs           []string
	OIDCRequiredClaims        map[string]string
	ServiceAccountKeyFiles    []string                // --service-account-key-file
	ServiceAccountLookup      bool                    // --service-account-lookup
	ServiceAccountIssuers     []string                // --service-account-issuer    JWT 签名颁发者
	APIAudiences              authenticator.Audiences // 预先规定的调用者们  , 目前只有一个 https://kubernetes.default.svc.cluster.local
	WebhookTokenAuthnVersion  string                  // 代码写死 v1beta1
	WebhookTokenAuthnCacheTTL time.Duration
	// WebhookRetryBackoff specifies the backoff parameters for the authentication webhook retry logic.
	// This allows us to configure the sleep time at each iteration and the maximum number of retries allowed
	// before we fail the webhook call in order to limit the fan out that ensues when the system is degraded.
	WebhookRetryBackoff *wait.Backoff

	TokenSuccessCacheTTL time.Duration
	TokenFailureCacheTTL time.Duration

	RequestHeaderConfig *authenticatorfactory.RequestHeaderConfig

	// TODO, 这是整个配置中唯一不可序列化的部分.将其分解到客户配置中
	ServiceAccountTokenGetter   serviceaccount.ServiceAccountTokenGetter
	SecretsWriter               typedv1core.SecretsGetter
	BootstrapTokenAuthenticator authenticator.Token                   // 缓存读取
	ClientCAContentProvider     dynamiccertificates.CAContentProvider // 用于验证客户证书,如果这个值为零,那么相互TLS被禁用.

	WebhookTokenAuthnConfigFile string           // egressDialer相关的配置信息
	CustomDial                  utilnet.DialFunc // 可选字段,用于连接webhook自定义拨号功能   egressDialer
}

// New 返回一个验证器请求、支持标准Kubernetes身份验证机制
func (config Config) New() (authenticator.Request, *spec.SecurityDefinitions, error) {
	// DefaultBuildHandlerChain
	// https://kubernetes.io/zh/docs/reference/access-authn-authz/authentication/
	var authenticators []authenticator.Request
	var tokenAuthenticators []authenticator.Token
	securityDefinitions := spec.SecurityDefinitions{}

	// front-proxy, BasicAuth methods, local first, then remote
	// 如果需要,添加前端代理身份验证器
	if config.RequestHeaderConfig != nil {
		requestHeaderAuthenticator := headerrequest.NewDynamicVerifyOptionsSecure( // 动态认证
			config.RequestHeaderConfig.CAContentProvider.VerifyOptions,
			config.RequestHeaderConfig.AllowedClientNames,  // [front-proxy-client]
			config.RequestHeaderConfig.UsernameHeaders,     // [X-Remote-User]
			config.RequestHeaderConfig.GroupHeaders,        // [X-Remote-Group]
			config.RequestHeaderConfig.ExtraHeaderPrefixes, // [X-Remote-Extra-]
		)
		var _ = requestHeaderAuthenticator.(*x509.Verifier).AuthenticateRequest
		authenticators = append(authenticators, authenticator.WrapAudienceAgnosticRequest(config.APIAudiences, requestHeaderAuthenticator))
	}

	// X509 methods
	if config.ClientCAContentProvider != nil {
		certAuth := x509.NewDynamic(config.ClientCAContentProvider.VerifyOptions, x509.CommonNameUserConversion)
		var _ = certAuth.AuthenticateRequest
		authenticators = append(authenticators, certAuth)
	}
	// ---------------------------------🔽  token 认证 -----------------------------------------------
	{
		// Bearer token methods, local first, then remote
		// 从本地的csv 认证文件加载用户
		if len(config.TokenAuthFile) > 0 {
			tokenAuth, err := newAuthenticatorFromTokenFile(config.TokenAuthFile)
			if err != nil {
				return nil, nil, err
			}
			var _ = tokenAuth.(*tokenfile.TokenAuthenticator).AuthenticateToken // ✅
			tokenAuthenticators = append(tokenAuthenticators, authenticator.WrapAudienceAgnosticToken(config.APIAudiences, tokenAuth))
		}
		if len(config.ServiceAccountKeyFiles) > 0 { // --service-account-key-file
			serviceAccountAuth, err := newLegacyServiceAccountAuthenticator(
				config.ServiceAccountKeyFiles, // --service-account-key-file
				config.ServiceAccountLookup,   // --service-account-lookup
				config.APIAudiences,           // --service-account-issuer	https://kubernetes.default.svc.cluster.local     jwt证书颁发者
				config.ServiceAccountTokenGetter,
				config.SecretsWriter,
			)
			if err != nil {
				return nil, nil, err
			}
			var _ = serviceAccountAuth.(*serviceaccount.JwtTokenAuthenticator).AuthenticateToken // ✅
			tokenAuthenticators = append(tokenAuthenticators, serviceAccountAuth)
		}
		if len(config.ServiceAccountIssuers) > 0 { // --service-account-issuer
			serviceAccountAuth, err := newServiceAccountAuthenticator(config.ServiceAccountIssuers, config.ServiceAccountKeyFiles, config.APIAudiences, config.ServiceAccountTokenGetter)
			if err != nil {
				return nil, nil, err
			}
			var _ = serviceAccountAuth.(*serviceaccount.JwtTokenAuthenticator).AuthenticateToken // ✅
			tokenAuthenticators = append(tokenAuthenticators, serviceAccountAuth)
		}
		if config.BootstrapToken {
			if config.BootstrapTokenAuthenticator != nil {
				var _ = new(authenticator.AudAgnosticTokenAuthenticator).AuthenticateToken // ✅
				var _ = new(bootstrap.TokenAuthenticator).AuthenticateToken                // ✅
				tokenAuthenticators = append(tokenAuthenticators, authenticator.WrapAudienceAgnosticToken(config.APIAudiences, config.BootstrapTokenAuthenticator))
			}
		}
		if len(config.OIDCIssuerURL) > 0 && len(config.OIDCClientID) > 0 {
			// TODO(enj): 当OIDC支持CA重载时,清除Notifier和ControllerRunner bit位
			var oidcCAContent oidc.CAContentProvider
			if len(config.OIDCCAFile) != 0 {
				var oidcCAErr error
				oidcCAContent, oidcCAErr = dynamiccertificates.NewDynamicCAContentFromFile("oidc-authenticator", config.OIDCCAFile)
				if oidcCAErr != nil {
					return nil, nil, oidcCAErr
				}
			}

			oidcAuth, err := newAuthenticatorFromOIDCIssuerURL(oidc.Options{
				IssuerURL:            config.OIDCIssuerURL,
				ClientID:             config.OIDCClientID,
				CAContentProvider:    oidcCAContent,
				UsernameClaim:        config.OIDCUsernameClaim,
				UsernamePrefix:       config.OIDCUsernamePrefix,
				GroupsClaim:          config.OIDCGroupsClaim,
				GroupsPrefix:         config.OIDCGroupsPrefix,
				SupportedSigningAlgs: config.OIDCSigningAlgs,
				RequiredClaims:       config.OIDCRequiredClaims,
			})
			if err != nil {
				return nil, nil, err
			}
			var _ = new(oidc.Authenticator).AuthenticateToken
			var _ = new(authenticator.AudAgnosticTokenAuthenticator).AuthenticateToken
			tokenAuthenticators = append(tokenAuthenticators,
				authenticator.WrapAudienceAgnosticToken(config.APIAudiences, oidcAuth),
			)
		}
		if len(config.WebhookTokenAuthnConfigFile) > 0 { // kube config格式的token认证webhook配置文件.API服务器将查询远程服务以确定承载令牌的身份验证.
			webhookTokenAuth, err := newWebhookTokenAuthenticator(config)
			if err != nil {
				return nil, nil, err
			}
			var _ = new(webhook.WebhookTokenAuthenticator).AuthenticateToken                  // ✅
			var _ = webhookTokenAuth.(*tokencache.CachedTokenAuthenticator).AuthenticateToken // ✅
			tokenAuthenticators = append(tokenAuthenticators, webhookTokenAuth)
		}

		if len(tokenAuthenticators) > 0 {
			// 联合令牌验证器
			var _ = new(tokenunion.UnionAuthTokenHandler).AuthenticateToken // ✅
			tokenAuth := tokenunion.New(tokenAuthenticators...)
			// 可选地缓存身份验证结果
			if config.TokenSuccessCacheTTL > 0 || config.TokenFailureCacheTTL > 0 {
				var _ = new(tokencache.CachedTokenAuthenticator).AuthenticateToken // ✅
				tokenAuth = tokencache.New(tokenAuth, true, config.TokenSuccessCacheTTL, config.TokenFailureCacheTTL)
			}

			var _ = new(bearertoken.Authenticator).AuthenticateRequest       // ✅
			var _ = new(websocket.ProtocolAuthenticator).AuthenticateRequest // ✅

			authenticators = append(authenticators,
				bearertoken.New(tokenAuth),
				websocket.NewProtocolAuthenticator(tokenAuth),
			)
			securityDefinitions["BearerToken"] = &spec.SecurityScheme{
				SecuritySchemeProps: spec.SecuritySchemeProps{
					Type:        "apiKey",
					Name:        "authorization",
					In:          "header",
					Description: "Bearer Token authentication",
				},
			}
		}
	}
	// ---------------------------------🔼  token 认证 -----------------------------------------------

	if len(authenticators) == 0 {
		if config.Anonymous {
			return anonymous.NewAuthenticator(), &securityDefinitions, nil
		}
		return nil, &securityDefinitions, nil
	}

	authenticator := union.New(authenticators...)
	var _ = new(group.AuthenticatedGroupAdder).AuthenticateRequest // ✅
	authenticator = group.NewAuthenticatedGroupAdder(authenticator)

	if config.Anonymous {
		// 如果认证器链返回错误,则返回错误（不将错误的令牌或无效的用户名/密码组合视为匿名）.
		var _ = new(union.UnionAuthRequestHandler).AuthenticateRequest // ✅
		authenticator = union.NewFailOnError(authenticator, anonymous.NewAuthenticator())
	}

	return authenticator, &securityDefinitions, nil
}

// IsValidServiceAccountKeyFile 如果可以从给定文件中读取有效的RSA公钥,则返回true
func IsValidServiceAccountKeyFile(file string) bool {
	_, err := keyutil.PublicKeysFromFile(file)
	return err == nil
}

// ✅
func newAuthenticatorFromTokenFile(tokenAuthFile string) (authenticator.Token, error) {
	tokenAuthenticator, err := tokenfile.NewCSV(tokenAuthFile)
	if err != nil {
		return nil, err
	}

	return tokenAuthenticator, nil
}

// newAuthenticatorFromOIDCIssuerURL returns an authenticator.Token or an error.
func newAuthenticatorFromOIDCIssuerURL(opts oidc.Options) (authenticator.Token, error) {
	const noUsernamePrefix = "-"

	if opts.UsernamePrefix == "" && opts.UsernameClaim != "email" {
		// Old behavior. If a usernamePrefix isn't provided, prefix all claims other than "email"
		// with the issuerURL.
		//
		// See https://github.com/kubernetes/kubernetes/issues/31380
		opts.UsernamePrefix = opts.IssuerURL + "#"
	}

	if opts.UsernamePrefix == noUsernamePrefix {
		// Special value indicating usernames shouldn't be prefixed.
		opts.UsernamePrefix = ""
	}

	tokenAuthenticator, err := oidc.New(opts)
	if err != nil {
		return nil, err
	}

	return tokenAuthenticator, nil
}

// 内置的sa认证
func newLegacyServiceAccountAuthenticator(keyfiles []string, lookup bool, apiAudiences authenticator.Audiences, serviceAccountGetter serviceaccount.ServiceAccountTokenGetter, secretsWriter typedv1core.SecretsGetter) (authenticator.Token, error) {
	allPublicKeys := []interface{}{}
	for _, keyfile := range keyfiles {
		publicKeys, err := keyutil.PublicKeysFromFile(keyfile)
		if err != nil {
			return nil, err
		}
		allPublicKeys = append(allPublicKeys, publicKeys...)
	}

	tokenAuthenticator := serviceaccount.JWTTokenAuthenticator(
		[]string{serviceaccount.LegacyIssuer},
		allPublicKeys,
		apiAudiences,
		serviceaccount.NewLegacyValidator(lookup, serviceAccountGetter, secretsWriter),
	)
	return tokenAuthenticator, nil
}

func newServiceAccountAuthenticator(issuers []string, keyfiles []string, apiAudiences authenticator.Audiences, serviceAccountGetter serviceaccount.ServiceAccountTokenGetter) (authenticator.Token, error) {
	allPublicKeys := []interface{}{}
	for _, keyfile := range keyfiles {
		publicKeys, err := keyutil.PublicKeysFromFile(keyfile)
		if err != nil {
			return nil, err
		}
		allPublicKeys = append(allPublicKeys, publicKeys...)
	}

	tokenAuthenticator := serviceaccount.JWTTokenAuthenticator(
		issuers,
		allPublicKeys,
		apiAudiences,
		serviceaccount.NewValidator(serviceAccountGetter),
	)
	return tokenAuthenticator, nil
}

func newWebhookTokenAuthenticator(config Config) (authenticator.Token, error) {
	if config.WebhookRetryBackoff == nil {
		return nil, errors.New("未指定认证webhook的重试回退参数")
	}

	clientConfig, err := webhookutil.LoadKubeconfig(config.WebhookTokenAuthnConfigFile, config.CustomDial)
	if err != nil {
		return nil, err
	}
	webhookTokenAuthenticator, err := webhook.New(clientConfig, config.WebhookTokenAuthnVersion, config.APIAudiences, *config.WebhookRetryBackoff)
	if err != nil {
		return nil, err
	}

	return tokencache.New(webhookTokenAuthenticator, false, config.WebhookTokenAuthnCacheTTL, config.WebhookTokenAuthnCacheTTL), nil
}
