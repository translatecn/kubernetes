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

package x509

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
)

/*
 * By default, the following metric is defined as falling under
 * ALPHA stability level https://github.com/kubernetes/enhancements/blob/master/keps/sig-instrumentation/1209-metrics-stability/kubernetes-control-plane-metrics-stability.md#stability-classes)
 *
 * Promoting the stability level of the metric is a responsibility of the component owner, since it
 * involves explicitly acknowledging support for the metric across multiple releases, in accordance with
 * the metric stability policy.
 */
var clientCertificateExpirationHistogram = metrics.NewHistogram(
	&metrics.HistogramOpts{
		Namespace: "apiserver",
		Subsystem: "client",
		Name:      "certificate_expiration_seconds",
		Help:      "Distribution of the remaining lifetime on the certificate used to authenticate a request.",
		Buckets: []float64{
			0,
			1800,     // 30 minutes
			3600,     // 1 hour
			7200,     // 2 hours
			21600,    // 6 hours
			43200,    // 12 hours
			86400,    // 1 day
			172800,   // 2 days
			345600,   // 4 days
			604800,   // 1 week
			2592000,  // 1 month
			7776000,  // 3 months
			15552000, // 6 months
			31104000, // 1 year
		},
		StabilityLevel: metrics.ALPHA,
	},
)

func init() {
	legacyregistry.MustRegister(clientCertificateExpirationHistogram)
}

// UserConversion defines an interface for extracting user info from a client certificate chain
type UserConversion interface {
	User(chain []*x509.Certificate) (*authenticator.Response, bool, error)
}

type UserConversionFunc func(chain []*x509.Certificate) (*authenticator.Response, bool, error)

// User implements x509.UserConversion
func (f UserConversionFunc) User(chain []*x509.Certificate) (*authenticator.Response, bool, error) {
	return f(chain)
}

func columnSeparatedHex(d []byte) string {
	h := strings.ToUpper(hex.EncodeToString(d))
	var sb strings.Builder
	for i, r := range h {
		sb.WriteRune(r)
		if i%2 == 1 && i != len(h)-1 {
			sb.WriteRune(':')
		}
	}
	return sb.String()
}

func certificateIdentifier(c *x509.Certificate) string {
	return fmt.Sprintf(
		"SN=%d, SKID=%s, AKID=%s",
		c.SerialNumber,
		columnSeparatedHex(c.SubjectKeyId),
		columnSeparatedHex(c.AuthorityKeyId),
	)
}

// VerifyOptionFunc is function which provides a shallow copy of the VerifyOptions to the authenticator.  This allows
// for cases where the options (particularly the CAs) can change.  If the bool is false, then the returned VerifyOptions
// are ignored and the authenticator will express "no opinion".  This allows a clear signal for cases where a CertPool
// is eventually expected, but not currently present.
type VerifyOptionFunc func() (x509.VerifyOptions, bool)

// Authenticator 从已验证的客户端证书中提取用户信息
type Authenticator struct {
	verifyOptionsFn VerifyOptionFunc
	user            UserConversion
}

// New returns a request.Authenticator that verifies client certificates using the provided
// VerifyOptions, and converts valid certificate chains into user.Info using the provided UserConversion
func New(opts x509.VerifyOptions, user UserConversion) *Authenticator {
	return NewDynamic(StaticVerifierFn(opts), user)
}

// NewDynamic 返回一个请求.验证器,使用提供的方法验证客户端证书
// VerifyOptionFunc(可能是动态的),并将有效的证书链转换为用户.信息使用提供的UserConversion
func NewDynamic(verifyOptionsFn VerifyOptionFunc, user UserConversion) *Authenticator {
	return &Authenticator{verifyOptionsFn, user}
}

// AuthenticateRequest authenticates the request using presented client certificates
func (a *Authenticator) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	if req.TLS == nil || len(req.TLS.PeerCertificates) == 0 {
		return nil, false, nil
	}

	// Use intermediates, if provided
	optsCopy, ok := a.verifyOptionsFn()
	// if there are intentionally no verify options, then we cannot authenticate this request
	if !ok {
		return nil, false, nil
	}
	// Intermediates 中间证书是一个可选的证书池,它不是信任anchors,但可用于形成从叶证书到根证书的链.
	// 客户端证书
	if optsCopy.Intermediates == nil && len(req.TLS.PeerCertificates) > 1 {
		optsCopy.Intermediates = x509.NewCertPool()
		for _, intermediate := range req.TLS.PeerCertificates[1:] {
			optsCopy.Intermediates.AddCert(intermediate)
		}
	}

	remaining := req.TLS.PeerCertificates[0].NotAfter.Sub(time.Now())
	clientCertificateExpirationHistogram.WithContext(req.Context()).Observe(remaining.Seconds())
	chains, err := req.TLS.PeerCertificates[0].Verify(optsCopy)
	if err != nil {
		return nil, false, fmt.Errorf(
			"verifying certificate %s failed: %w",
			certificateIdentifier(req.TLS.PeerCertificates[0]),
			err,
		)
	}

	var errlist []error
	for _, chain := range chains {
		user, ok, err := a.user.User(chain)
		if err != nil {
			errlist = append(errlist, err)
			continue
		}

		if ok {
			return user, ok, err
		}
	}
	return nil, false, utilerrors.NewAggregate(errlist)
}

// Verifier 在请求上验证客户端证书,然后委托给封装的身份验证
type Verifier struct {
	verifyOptionsFn    VerifyOptionFunc
	auth               authenticator.Request
	allowedCommonNames StringSliceProvider // 包含经过验证的证书允许具有的通用名称.如果为空,则允许所有已验证的证书.
}

// NewVerifier create a request.Authenticator by verifying a client cert on the request, then delegating to the wrapped auth
func NewVerifier(opts x509.VerifyOptions, auth authenticator.Request, allowedCommonNames sets.String) authenticator.Request {
	return NewDynamicCAVerifier(StaticVerifierFn(opts), auth, StaticStringSlice(allowedCommonNames.List()))
}

// NewDynamicCAVerifier 创建请求.验证程序,方法是验证请求上的客户端证书,然后委托给封装的验证程序
func NewDynamicCAVerifier(verifyOptionsFn VerifyOptionFunc, auth authenticator.Request, allowedCommonNames StringSliceProvider) authenticator.Request {
	return &Verifier{verifyOptionsFn, auth, allowedCommonNames}
}

// AuthenticateRequest 验证客户端证书,然后委托给包装的身份验证程序.
func (a *Verifier) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	if req.TLS == nil || len(req.TLS.PeerCertificates) == 0 {
		return nil, false, nil
	}

	// Use intermediates, if provided
	optsCopy, ok := a.verifyOptionsFn()
	if !ok {
		return nil, false, nil
	}
	// Intermediates 中间证书是一个可选的证书池,它不是信任anchors,但可用于形成从叶证书到根证书的链.
	// 客户端证书
	if optsCopy.Intermediates == nil && len(req.TLS.PeerCertificates) > 1 {
		optsCopy.Intermediates = x509.NewCertPool()
		for _, intermediate := range req.TLS.PeerCertificates[1:] {
			optsCopy.Intermediates.AddCert(intermediate)
		}
	}

	if _, err := req.TLS.PeerCertificates[0].Verify(optsCopy); err != nil {
		return nil, false, err
	}
	if err := a.verifySubject(req.TLS.PeerCertificates[0].Subject); err != nil {
		return nil, false, err
	}
	return a.auth.AuthenticateRequest(req)
}

func (a *Verifier) verifySubject(subject pkix.Name) error {
	// No CN restrictions
	if len(a.allowedCommonNames.Value()) == 0 { // [front-proxy-client]
		return nil
	}
	// Enforce CN restrictions
	for _, allowedCommonName := range a.allowedCommonNames.Value() {
		if allowedCommonName == subject.CommonName {
			return nil
		}
	}
	return fmt.Errorf("x509: subject with cn=%s is not in the allowed list", subject.CommonName)
}

// DefaultVerifyOptions returns VerifyOptions that use the system root certificates, current time,
// and requires certificates to be valid for client auth (x509.ExtKeyUsageClientAuth)
func DefaultVerifyOptions() x509.VerifyOptions {
	return x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

// CommonNameUserConversion 使用主题的CommonName从证书链构建用户信息
var CommonNameUserConversion = UserConversionFunc(func(chain []*x509.Certificate) (*authenticator.Response, bool, error) {
	if len(chain[0].Subject.CommonName) == 0 {
		return nil, false, nil
	}
	return &authenticator.Response{
		User: &user.DefaultInfo{
			Name:   chain[0].Subject.CommonName,
			Groups: chain[0].Subject.Organization,
		},
	}, true, nil
})
