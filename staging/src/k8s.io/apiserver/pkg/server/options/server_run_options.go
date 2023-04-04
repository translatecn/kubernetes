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
	"net"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/server"
	utilfeature "k8s.io/apiserver/pkg/util/feature"

	"github.com/spf13/pflag"
)

// ServerRunOptions contains the options while running a generic api server.
type ServerRunOptions struct {
	AdvertiseAddress            net.IP        // --advertise-address=设置
	CorsAllowedOriginList       []string      //
	HSTSDirectives              []string      //
	ExternalHost                string        // api-server对外提供访问的入口,  域名或者IP
	MaxRequestsInFlight         int           //
	MaxMutatingRequestsInFlight int           //
	RequestTimeout              time.Duration //
	GoawayChance                float64       //
	LivezGracePeriod            time.Duration //
	MinRequestTimeout           int           //
	ShutdownDelayDuration       time.Duration //
	JSONPatchMaxCopyBytes       int64         // 我们故意没有为这个选项添加flag。
	MaxRequestBodyBytes         int64         //
	EnablePriorityAndFairness   bool          // 优先级和公平性管理
	ShutdownSendRetryAfter      bool          //
}

func NewServerRunOptions() *ServerRunOptions {
	defaults := server.NewConfig(serializer.CodecFactory{}) // ✅
	return &ServerRunOptions{                               // 程序运行初的默认值
		MaxRequestsInFlight:         defaults.MaxRequestsInFlight,
		MaxMutatingRequestsInFlight: defaults.MaxMutatingRequestsInFlight,
		RequestTimeout:              defaults.RequestTimeout,
		LivezGracePeriod:            defaults.LivezGracePeriod,
		MinRequestTimeout:           defaults.MinRequestTimeout,
		ShutdownDelayDuration:       defaults.ShutdownDelayDuration,
		JSONPatchMaxCopyBytes:       defaults.JSONPatchMaxCopyBytes,
		MaxRequestBodyBytes:         defaults.MaxRequestBodyBytes,
		EnablePriorityAndFairness:   true,
		ShutdownSendRetryAfter:      false,
	}
}

// ApplyTo applies the run options to the method receiver and returns self
func (s *ServerRunOptions) ApplyTo(c *server.Config) error {
	c.CorsAllowedOriginList = s.CorsAllowedOriginList
	c.HSTSDirectives = s.HSTSDirectives
	c.ExternalAddress = s.ExternalHost
	c.MaxRequestsInFlight = s.MaxRequestsInFlight
	c.MaxMutatingRequestsInFlight = s.MaxMutatingRequestsInFlight
	c.LivezGracePeriod = s.LivezGracePeriod
	c.RequestTimeout = s.RequestTimeout
	c.GoawayChance = s.GoawayChance
	c.MinRequestTimeout = s.MinRequestTimeout
	c.ShutdownDelayDuration = s.ShutdownDelayDuration
	c.JSONPatchMaxCopyBytes = s.JSONPatchMaxCopyBytes
	c.MaxRequestBodyBytes = s.MaxRequestBodyBytes
	c.PublicAddress = s.AdvertiseAddress
	c.ShutdownSendRetryAfter = s.ShutdownSendRetryAfter

	return nil
}

// DefaultAdvertiseAddress 如果未设置,则设置 AdvertiseAddress 字段.该字段将根据SecureServingOptions进行设置.
func (s *ServerRunOptions) DefaultAdvertiseAddress(secure *SecureServingOptions) error {
	if secure == nil {
		return nil
	}

	if s.AdvertiseAddress == nil || s.AdvertiseAddress.IsUnspecified() { // 没有指定具体IP
		hostIP, err := secure.DefaultExternalAddress()
		if err != nil {
			return fmt.Errorf("无法找到合适的网络地址.错误='%v'.尝试直接设置AdvertiseAddress或提供有效的BindAddress来修复此问题.", err)
		}
		s.AdvertiseAddress = hostIP
	}

	return nil
}

// Validate checks validation of ServerRunOptions
func (s *ServerRunOptions) Validate() []error {
	var errors []error

	if s.LivezGracePeriod < 0 {
		errors = append(errors, fmt.Errorf("--livez-grace-period can not be a negative value"))
	}

	if s.MaxRequestsInFlight < 0 {
		errors = append(errors, fmt.Errorf("--max-requests-inflight can not be negative value"))
	}
	if s.MaxMutatingRequestsInFlight < 0 {
		errors = append(errors, fmt.Errorf("--max-mutating-requests-inflight can not be negative value"))
	}

	if s.RequestTimeout.Nanoseconds() < 0 {
		errors = append(errors, fmt.Errorf("--request-timeout can not be negative value"))
	}

	if s.GoawayChance < 0 || s.GoawayChance > 0.02 {
		errors = append(errors, fmt.Errorf("--goaway-chance can not be less than 0 or greater than 0.02"))
	}

	if s.MinRequestTimeout < 0 {
		errors = append(errors, fmt.Errorf("--min-request-timeout can not be negative value"))
	}

	if s.ShutdownDelayDuration < 0 {
		errors = append(errors, fmt.Errorf("--shutdown-delay-duration can not be negative value"))
	}

	if s.JSONPatchMaxCopyBytes < 0 {
		errors = append(errors, fmt.Errorf("ServerRunOptions.JSONPatchMaxCopyBytes can not be negative value"))
	}

	if s.MaxRequestBodyBytes < 0 {
		errors = append(errors, fmt.Errorf("ServerRunOptions.MaxRequestBodyBytes can not be negative value"))
	}

	if err := validateHSTSDirectives(s.HSTSDirectives); err != nil {
		errors = append(errors, err)
	}
	return errors
}

func validateHSTSDirectives(hstsDirectives []string) error {
	// HSTS Headers format: Strict-Transport-Security:max-age=expireTime [;includeSubDomains] [;preload]
	// See https://tools.ietf.org/html/rfc6797#section-6.1 for more information
	allErrors := []error{}
	for _, hstsDirective := range hstsDirectives {
		if len(strings.TrimSpace(hstsDirective)) == 0 {
			allErrors = append(allErrors, fmt.Errorf("empty value in strict-transport-security-directives"))
			continue
		}
		if hstsDirective != "includeSubDomains" && hstsDirective != "preload" {
			maxAgeDirective := strings.Split(hstsDirective, "=")
			if len(maxAgeDirective) != 2 || maxAgeDirective[0] != "max-age" {
				allErrors = append(allErrors, fmt.Errorf("--strict-transport-security-directives invalid, allowed values: max-age=expireTime, includeSubDomains, preload. see https://tools.ietf.org/html/rfc6797#section-6.1 for more information"))
			}
		}
	}
	return errors.NewAggregate(allErrors)
}

// AddUniversalFlags 通用flag
func (s *ServerRunOptions) AddUniversalFlags(fs *pflag.FlagSet) {
	fs.IPVar(&s.AdvertiseAddress, "advertise-address", s.AdvertiseAddress, "将api-server通告给集群成员的IP地址.该地址必须能被集群的其他组件访问.如果为空,则使用--bind-address.如果没有指定--bind-address,则使用主机的默认接口.")
	fs.StringSliceVar(&s.CorsAllowedOriginList, "cors-allowed-origins", s.CorsAllowedOriginList, "CORS允许的源列表,以逗号分隔.允许的原点可以是支持子域匹配的正则表达式.如果此列表为空,则CORS将不会启用.")
	// https://zhuanlan.zhihu.com/p/130946490
	fs.StringSliceVar(&s.HSTSDirectives, "strict-transport-security-directives", s.HSTSDirectives,
		"HSTS指令列表,逗号分隔.例如:'max-age=31536000,includeSubDomains,preload'")
	fs.StringVar(&s.ExternalHost, "external-hostname", s.ExternalHost, "为主机生成外部化url时使用的主机名(例如Swagger API Docs或OpenID Discovery).")
	deprecatedMasterServiceNamespace := metav1.NamespaceDefault
	fs.StringVar(&deprecatedMasterServiceNamespace, "master-service-namespace", deprecatedMasterServiceNamespace, "DEPRECATED:将Kubernetes主服务注入pod的命名空间.")
	fs.MarkDeprecated("master-service-namespace", "这个标志将在v1.27中被移除")

	fs.DurationVar(&s.RequestTimeout, "request-timeout", s.RequestTimeout, "这是请求的默认请求超时,但对于特定类型的请求,可能会被诸如--min-request-timeout之类的标志覆盖.")
	fs.IntVar(&s.MinRequestTimeout, "min-request-timeout", s.MinRequestTimeout, "请求最小超时时间")

	fs.Float64Var(&s.GoawayChance, "goaway-chance", s.GoawayChance,
		"多apiserver 时,为了防止HTTP/2客户端卡在单个apisserver上,随机关闭一个连接(超时)."+
			"此参数设置将发送超时的请求的百分比.最小值是0(关闭),最大值是0.02(1/50请求);.001(1/1000)是推荐的起始点.")

	fs.DurationVar(&s.LivezGracePeriod, "livez-grace-period", s.LivezGracePeriod,
		"该选项表示apiserver完成其启动序列并启动所需的最大时间."+
			"从apiserver的开始时间到这个时间已经过去,/livez将假设未完成的启动后钩子将成功完成,因此返回true.")

	fs.BoolVar(&s.EnablePriorityAndFairness, "enable-priority-and-fairness", s.EnablePriorityAndFairness,
		"如果为true并且APIPriorityAndFairness特性已启用,则将max-in-flight处理程序替换为具有优先级和公平性的队列和调度增强处理程序")
	fs.IntVar(&s.MaxRequestsInFlight, "max-requests-inflight", s.MaxRequestsInFlight,
		"如果--enable-priority-and-fairness为真,--max-requests-inflight 和 --max-mutating-requests-inflight 相加以确定服务器的总并发限制(必须为正)."+
			"否则,该标志将限制运行中的非突变请求的最大数量,如果值为零则完全禁用该限制.")
	fs.IntVar(&s.MaxMutatingRequestsInFlight, "max-mutating-requests-inflight", s.MaxMutatingRequestsInFlight, "突发流量上限")

	fs.DurationVar(&s.ShutdownDelayDuration, "shutdown-delay-duration", s.ShutdownDelayDuration,
		"延迟终止时间。在此期间，服务器继续正常地为请求提供服务。 /healthz和/livez  返回成功，但是/readyz立即返回失败。")

	fs.BoolVar(&s.ShutdownSendRetryAfter, "shutdown-send-retry-after", s.ShutdownSendRetryAfter,
		"如果为true, HTTP服务器将继续监听，直到所有非长时间运行的请求被耗尽，在此窗口期间，所有传入的请求将被拒绝，"+
			"状态码为429，响应头为'Retry-After'，此外还设置了'Connection: close'响应头，以便在空闲时断开TCP连接。")

	utilfeature.DefaultMutableFeatureGate.AddFlag(fs)
}
