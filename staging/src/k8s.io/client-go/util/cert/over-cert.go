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

package cert

import (
	"bytes"
	"crypto"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"k8s.io/client-go/util/keyutil"
	netutils "k8s.io/utils/net"
)

const duration365d = time.Hour * 24 * 365

// Config 包含创建证书所需的基本字段  ,kube-apiserver 将提取的 User、Group 作为 RBAC 授权的用户标识；
type Config struct {
	CommonName   string   // CN：Common Name：kube-apiserver 从证书中提取该字段作为请求的用户名 (User Name),浏览器使用该字段验证网站是否合法；
	Organization []string // O：Organization：kube-apiserver 从证书中提取该字段作为请求用户所属的组 (Group)；
	AltNames     AltNames
	Usages       []x509.ExtKeyUsage
}

// AltNames 包含域名和IP地址,将被添加到API server的x509证书SubAltNames字段.这些值将直接传递给 x509.cert 对象.
type AltNames struct {
	DNSNames []string
	IPs      []net.IP
}

// NewSelfSignedCACert 创建CA证书
func NewSelfSignedCACert(cfg Config, key crypto.Signer) (*x509.Certificate, error) {
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName:   cfg.CommonName,
			Organization: cfg.Organization,
		},
		DNSNames:              []string{cfg.CommonName},
		NotBefore:             now.UTC(),
		NotAfter:              now.Add(duration365d * 10).UTC(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDERBytes, err := x509.CreateCertificate(cryptorand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDERBytes)
}

// GenerateSelfSignedCertKey 为指定主机创建自签名证书和密钥.
// Host可以是IP或DNS名称
// 您还可以为证书指定额外的主题alt名称(ip或dns名称).
func GenerateSelfSignedCertKey(host string, alternateIPs []net.IP, alternateDNS []string) ([]byte, []byte, error) {
	return GenerateSelfSignedCertKeyWithFixtures(host, alternateIPs, alternateDNS, "")
}

// GenerateSelfSignedCertKeyWithFixtures 为给定主机创建自签名证书和密钥.
// Host可以是IP或DNS名称.您还可以指定额外的主题alt名称(ip或dns名称) 获取证书.
// If fixtureDirectory is non-empty, it is a directory path which can contain pre-generated certs. The format is:
// <host>_<ip>-<ip>_<alternateDNS>-<alternateDNS>.crt
// <host>_<ip>-<ip>_<alternateDNS>-<alternateDNS>.key
// Certs/keys not existing in that directory are created.
func GenerateSelfSignedCertKeyWithFixtures(host string, alternateIPs []net.IP, alternateDNS []string, fixtureDirectory string) ([]byte, []byte, error) {
	validFrom := time.Now().Add(-time.Hour) // 提前一小时有效,以避免因时钟偏差而产生薄片
	maxAge := time.Hour * 24 * 365          // 有效期一年的自签证书

	baseName := fmt.Sprintf("%s_%s_%s", host, strings.Join(ipsToStrings(alternateIPs), "-"), strings.Join(alternateDNS, "-"))
	certFixturePath := filepath.Join(fixtureDirectory, baseName+".crt")
	keyFixturePath := filepath.Join(fixtureDirectory, baseName+".key")
	if len(fixtureDirectory) > 0 {
		cert, err := os.ReadFile(certFixturePath)
		if err == nil {
			key, err := os.ReadFile(keyFixturePath)
			if err == nil {
				return cert, key, nil
			}
			return nil, nil, fmt.Errorf("cert %s can be read, but key %s cannot: %v", certFixturePath, keyFixturePath, err)
		}
		maxAge = 100 * time.Hour * 24 * 365 // 100 years fixtures
	}

	caKey, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("%s-ca@%d", host, time.Now().Unix()),
		},
		NotBefore: validFrom,
		NotAfter:  validFrom.Add(maxAge),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, // 加密证书、数字签名、证书签名
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	// https://juejin.cn/post/6976125107143966750
	caDERBytes, err := x509.CreateCertificate(cryptorand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	caCertificate, err := x509.ParseCertificate(caDERBytes)
	if err != nil {
		return nil, nil, err
	}

	priv, err := rsa.GenerateKey(cryptorand.Reader, 2048) // 生成秘钥
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("%s@%d", host, time.Now().Unix()),
		},
		NotBefore: validFrom,
		NotAfter:  validFrom.Add(maxAge),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := netutils.ParseIPSloppy(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
	}

	template.IPAddresses = append(template.IPAddresses, alternateIPs...)
	template.DNSNames = append(template.DNSNames, alternateDNS...)

	derBytes, err := x509.CreateCertificate(cryptorand.Reader, &template, caCertificate, &priv.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	// 通过CA生成证书
	certBuffer := bytes.Buffer{}
	if err := pem.Encode(&certBuffer, &pem.Block{Type: CertificateBlockType, Bytes: derBytes}); err != nil {
		return nil, nil, err
	}
	if err := pem.Encode(&certBuffer, &pem.Block{Type: CertificateBlockType, Bytes: caDERBytes}); err != nil {
		return nil, nil, err
	}

	// 生成密钥
	keyBuffer := bytes.Buffer{}
	if err := pem.Encode(&keyBuffer, &pem.Block{Type: keyutil.RSAPrivateKeyBlockType, Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return nil, nil, err
	}

	if len(fixtureDirectory) > 0 {
		if err := os.WriteFile(certFixturePath, certBuffer.Bytes(), 0644); err != nil {
			return nil, nil, fmt.Errorf("failed to write cert fixture to %s: %v", certFixturePath, err)
		}
		if err := os.WriteFile(keyFixturePath, keyBuffer.Bytes(), 0644); err != nil {
			return nil, nil, fmt.Errorf("failed to write key fixture to %s: %v", certFixturePath, err)
		}
	}

	return certBuffer.Bytes(), keyBuffer.Bytes(), nil
}

func ipsToStrings(ips []net.IP) []string {
	ss := make([]string, 0, len(ips))
	for _, ip := range ips {
		ss = append(ss, ip.String())
	}
	return ss
}
