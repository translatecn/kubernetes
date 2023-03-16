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
	"context"
	"fmt"
	"net"
	"path"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/pflag"
	"k8s.io/klog/v2"
	netutils "k8s.io/utils/net"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	cliflag "k8s.io/component-base/cli/flag"
)

type SecureServingOptions struct {
	BindAddress     net.IP                 // 0.0.0.0
	BindPort        int                    // 设置Listener时忽略,即使设置为0也会提供https服务. 6443
	BindNetwork     string                 // 是要绑定的网络类型-默认为"tcp",接受"tcp", "tcp4"和"tcp6".
	Required        bool                   // 设置为true表示BindPort不能为零.
	ExternalAddress net.IP                 // 发布的地址,即使BindAddress是环回地址.默认情况下,如果后面没有环回,则设置为BindAddress,或者为第一个主机接口地址.
	Listener        net.Listener           // Listener是安全服务器网络侦听器
	ServerCert      GeneratableKeyCert     // TLS证书信息是否用于提供安全流量
	SNICertKeys     []cliflag.NamedCertKey // 为SNI支持提供安全流量
	// CipherSuites is the list of allowed cipher suites for the server.
	// Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants).
	CipherSuites []string
	// MinTLSVersion is the minimum TLS version supported.
	// Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants).
	MinTLSVersion string

	// HTTP2MaxStreamsPerConnection is the limit that the api server imposes on each client.
	// A value of zero means to use the default provided by golang's HTTP/2 support.
	HTTP2MaxStreamsPerConnection int

	// PermitPortSharing controls if SO_REUSEPORT is used when binding the port, which allows
	// more than one instance to bind on the same address and port.
	PermitPortSharing bool

	// PermitAddressSharing controls if SO_REUSEADDR is used when binding the port.
	PermitAddressSharing bool
}

type CertKey struct {
	CertFile string // 是一个包含pem编码的证书的文件,可能还有完整的证书链
	KeyFile  string // 文件中是否包含CertFile指定的pem编码的证书私钥
}

type GeneratableKeyCert struct {
	CertKey       CertKey                                    // 设置要使用的显式证书/密钥文件.
	CertDirectory string                                     // 证书路径
	PairName      string                                     // 是与CertDirectory一起用于生成证书和密钥文件名的名称.
	GeneratedCert dynamiccertificates.CertKeyContentProvider // 如果CertFile/KeyFile、CertDirectory/PairName没有设置,则将生成的证书保存在内存中.
	// FixtureDirectory 是一个目录,其中包含用于避免在测试期间重新生成cert的测试工具.
	// The format is:
	// <host>_<ip>-<ip>_<alternateDNS>-<alternateDNS>.crt
	// <host>_<ip>-<ip>_<alternateDNS>-<alternateDNS>.key
	FixtureDirectory string
}

func NewSecureServingOptions() *SecureServingOptions {
	return &SecureServingOptions{
		BindAddress: netutils.ParseIPSloppy("0.0.0.0"),
		BindPort:    443,
		ServerCert: GeneratableKeyCert{
			PairName:      "apiserver",
			CertDirectory: "apiserver.local.config/certificates",
		},
	}
}

func (s *SecureServingOptions) DefaultExternalAddress() (net.IP, error) {
	if s.ExternalAddress != nil && !s.ExternalAddress.IsUnspecified() {
		return s.ExternalAddress, nil
	}
	return utilnet.ResolveBindAddress(s.BindAddress)
}

// Validate 👌🏻
func (s *SecureServingOptions) Validate() []error {
	if s == nil {
		return nil
	}

	errors := []error{}

	if s.Required && s.BindPort < 1 || s.BindPort > 65535 {
		errors = append(errors, fmt.Errorf("--secure-port %v must be between 1 and 65535, inclusive. It cannot be turned off with 0", s.BindPort))
	} else if s.BindPort < 0 || s.BindPort > 65535 {
		errors = append(errors, fmt.Errorf("--secure-port %v must be between 0 and 65535, inclusive. 0 for turning off secure port", s.BindPort))
	}

	if (len(s.ServerCert.CertKey.CertFile) != 0 || len(s.ServerCert.CertKey.KeyFile) != 0) && s.ServerCert.GeneratedCert != nil {
		errors = append(errors, fmt.Errorf("cert/key file and in-memory certificate cannot both be set"))
	}

	return errors
}

func (s *SecureServingOptions) AddFlags(fs *pflag.FlagSet) {
	if s == nil {
		return
	}

	fs.IPVar(&s.BindAddress, "bind-address", s.BindAddress, "对外监听的IP")
	desc := "通过认证和授权提供HTTPS服务的端口。"
	if s.Required {
		desc += "不能用0来关闭。"
	} else {
		desc += "如果是0，则完全不提供HTTPS服务。"
	}
	fs.IntVar(&s.BindPort, "secure-port", s.BindPort, desc)
	fs.StringVar(&s.ServerCert.CertDirectory, "cert-dir", s.ServerCert.CertDirectory,
		"TLS证书所在的目录。如果提供了-tls-cert-file和-tls-private-key-file，这个标志将被忽略。")
	fs.StringVar(&s.ServerCert.CertKey.CertFile, "tls-cert-file", s.ServerCert.CertKey.CertFile,
		"包含HTTPS默认x509证书的文件。(如果有CA证书，则在服务器证书之后串联)。"+
			"如果启用了HTTPS服务，并且没有提供--tls-cert-file和--tls-private-key-file，将为public地址生成一个自签名的证书和密钥，并保存在由--cert-dir指定的目录中。")
	fs.StringVar(&s.ServerCert.CertKey.KeyFile, "tls-private-key-file", s.ServerCert.CertKey.KeyFile, "包含默认x509私钥匹配的文件 --tls-cert-file。")

	tlsCipherPreferredValues := cliflag.PreferredTLSCipherNames()
	tlsCipherInsecureValues := cliflag.InsecureTLSCipherNames()
	fs.StringSliceVar(&s.CipherSuites, "tls-cipher-suites", s.CipherSuites,
		"以逗号分隔的服务器密码套件列表。 如果省略，将使用默认的Go密码套件。"+
			"首选值: "+strings.Join(tlsCipherPreferredValues, ", ")+". \n"+
			"不安全的值: "+strings.Join(tlsCipherInsecureValues, ", ")+".")

	tlsPossibleVersions := cliflag.TLSPossibleVersions()
	fs.StringVar(&s.MinTLSVersion, "tls-min-version", s.MinTLSVersion,
		"支持的最小TLS版本。可能的值:"+strings.Join(tlsPossibleVersions, ", "))

	fs.Var(cliflag.NewNamedCertKeyArray(&s.SNICertKeys), "tls-sni-cert-key", "一对x509证书和私钥文件路径")

	fs.IntVar(&s.HTTP2MaxStreamsPerConnection, "http2-max-streams-per-connection", s.HTTP2MaxStreamsPerConnection,
		"服务器给客户的 HTTP/2连接中的最大流数量 的限制。0 意味着使用golang的默认值。")

	fs.BoolVar(&s.PermitPortSharing, "permit-port-sharing", s.PermitPortSharing,
		"如果为真，则在绑定端口时将使用SO_REUSEPORT，这允许多个实例在相同的地址和端口上绑定。(default=false)")

	fs.BoolVar(&s.PermitAddressSharing, "permit-address-sharing", s.PermitAddressSharing,
		"如果为true，绑定端口时将使用SO_REUSEADDR。这允许与通配符ip(如0.0.0.0)和特定ip并行绑定，并且避免等待内核在TIME_WAIT状态下释放套接字。(default=false)")
}

// ApplyTo fills up serving information in the server configuration.
func (s *SecureServingOptions) ApplyTo(config **server.SecureServingInfo) error {
	if s == nil {
		return nil
	}
	if s.BindPort <= 0 && s.Listener == nil {
		return nil
	}

	if s.Listener == nil {
		var err error
		addr := net.JoinHostPort(s.BindAddress.String(), strconv.Itoa(s.BindPort))

		c := net.ListenConfig{}

		ctls := multipleControls{}
		if s.PermitPortSharing {
			ctls = append(ctls, permitPortReuse)
		}
		if s.PermitAddressSharing {
			ctls = append(ctls, permitAddressReuse)
		}
		if len(ctls) > 0 {
			c.Control = ctls.Control
		}

		s.Listener, s.BindPort, err = CreateListener(s.BindNetwork, addr, c)
		if err != nil {
			return fmt.Errorf("failed to create listener: %v", err)
		}
	} else {
		if _, ok := s.Listener.Addr().(*net.TCPAddr); !ok {
			return fmt.Errorf("failed to parse ip and port from listener")
		}
		s.BindPort = s.Listener.Addr().(*net.TCPAddr).Port
		s.BindAddress = s.Listener.Addr().(*net.TCPAddr).IP
	}

	*config = &server.SecureServingInfo{
		Listener:                     s.Listener,
		HTTP2MaxStreamsPerConnection: s.HTTP2MaxStreamsPerConnection,
	}
	c := *config

	serverCertFile, serverKeyFile := s.ServerCert.CertKey.CertFile, s.ServerCert.CertKey.KeyFile
	// load main cert
	if len(serverCertFile) != 0 || len(serverKeyFile) != 0 {
		var err error
		c.Cert, err = dynamiccertificates.NewDynamicServingContentFromFiles("serving-cert", serverCertFile, serverKeyFile)
		if err != nil {
			return err
		}
	} else if s.ServerCert.GeneratedCert != nil {
		c.Cert = s.ServerCert.GeneratedCert
	}

	if len(s.CipherSuites) != 0 {
		cipherSuites, err := cliflag.TLSCipherSuites(s.CipherSuites)
		if err != nil {
			return err
		}
		c.CipherSuites = cipherSuites
	}

	var err error
	c.MinTLSVersion, err = cliflag.TLSVersion(s.MinTLSVersion)
	if err != nil {
		return err
	}

	// load SNI certs
	namedTLSCerts := make([]dynamiccertificates.SNICertKeyContentProvider, 0, len(s.SNICertKeys))
	for _, nck := range s.SNICertKeys {
		tlsCert, err := dynamiccertificates.NewDynamicSNIContentFromFiles("sni-serving-cert", nck.CertFile, nck.KeyFile, nck.Names...)
		namedTLSCerts = append(namedTLSCerts, tlsCert)
		if err != nil {
			return fmt.Errorf("failed to load SNI cert and key: %v", err)
		}
	}
	c.SNICerts = namedTLSCerts

	return nil
}

// MaybeDefaultWithSelfSignedCerts 共有地址,备用dns,备用ips
func (s *SecureServingOptions) MaybeDefaultWithSelfSignedCerts(publicAddress string, alternateDNS []string, alternateIPs []net.IP) error {
	if s == nil || (s.BindPort == 0 && s.Listener == nil) {
		return nil
	}
	keyCert := &s.ServerCert.CertKey
	if len(keyCert.CertFile) != 0 || len(keyCert.KeyFile) != 0 {
		return nil
	}

	canReadCertAndKey := false
	if len(s.ServerCert.CertDirectory) > 0 {
		if len(s.ServerCert.PairName) == 0 {
			return fmt.Errorf("PairName is required if CertDirectory is set")
		}
		keyCert.CertFile = path.Join(s.ServerCert.CertDirectory, s.ServerCert.PairName+".crt")
		keyCert.KeyFile = path.Join(s.ServerCert.CertDirectory, s.ServerCert.PairName+".key")
		if canRead, err := certutil.CanReadCertAndKey(keyCert.CertFile, keyCert.KeyFile); err != nil {
			return err
		} else {
			canReadCertAndKey = canRead
		}
	}

	if !canReadCertAndKey {
		// 将绑定地址或localhost添加到有效的备用地址中
		if s.BindAddress.IsUnspecified() {
			alternateDNS = append(alternateDNS, "localhost")
		} else {
			alternateIPs = append(alternateIPs, s.BindAddress)
		}

		if cert, key, err := certutil.GenerateSelfSignedCertKeyWithFixtures(publicAddress, alternateIPs, alternateDNS, s.ServerCert.FixtureDirectory); err != nil {
			return fmt.Errorf("unable to generate self signed cert: %v", err)
		} else if len(keyCert.CertFile) > 0 && len(keyCert.KeyFile) > 0 {
			if err := certutil.WriteCert(keyCert.CertFile, cert); err != nil {
				return err
			}
			if err := keyutil.WriteKey(keyCert.KeyFile, key); err != nil {
				return err
			}
			klog.Infof("Generated self-signed cert (%s, %s)", keyCert.CertFile, keyCert.KeyFile)
		} else {
			s.ServerCert.GeneratedCert, err = dynamiccertificates.NewStaticCertKeyContent("Generated self signed cert", cert, key)
			if err != nil {
				return err
			}
			klog.Infof("Generated self-signed cert in-memory")
		}
	}

	return nil
}

func CreateListener(network, addr string, config net.ListenConfig) (net.Listener, int, error) {
	if len(network) == 0 {
		network = "tcp"
	}

	ln, err := config.Listen(context.TODO(), network, addr)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to listen on %v: %v", addr, err)
	}

	// get port
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		ln.Close()
		return nil, 0, fmt.Errorf("invalid listen address: %q", ln.Addr().String())
	}

	return ln, tcpAddr.Port, nil
}

type multipleControls []func(network, addr string, conn syscall.RawConn) error

func (mcs multipleControls) Control(network, addr string, conn syscall.RawConn) error {
	for _, c := range mcs {
		if err := c(network, addr, conn); err != nil {
			return err
		}
	}
	return nil
}
