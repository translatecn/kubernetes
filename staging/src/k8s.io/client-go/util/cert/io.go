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
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
)

// CanReadCertAndKey 如果证书和密钥文件已经存在,则返回true,
// 否则返回false.如果丢失一个证书和密钥,返回错误.
func CanReadCertAndKey(certPath, keyPath string) (bool, error) {
	certReadable := canReadFile(certPath)
	keyReadable := canReadFile(keyPath)

	if certReadable == false && keyReadable == false {
		return false, nil
	}

	if certReadable == false {
		return false, fmt.Errorf("error reading %s, certificate and key must be supplied as a pair", certPath)
	}

	if keyReadable == false {
		return false, fmt.Errorf("error reading %s, certificate and key must be supplied as a pair", keyPath)
	}

	return true, nil
}

// If the file represented by path exists and
// readable, returns true otherwise returns false.
func canReadFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}

	defer f.Close()

	return true
}

// WriteCert 将pem编码的证书数据写入certPath.
// 证书文件将以文件模式0644创建.
// 如果证书文件已经存在,证书文件将被覆盖.
// certPath的父目录将根据需要创建,文件模式0755.
func WriteCert(certPath string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(certPath), os.FileMode(0755)); err != nil {
		return err
	}
	return os.WriteFile(certPath, data, os.FileMode(0644))
}

// NewPool returns an x509.CertPool containing the certificates in the given PEM-encoded file.
// Returns an error if the file could not be read, a certificate could not be parsed, or if the file does not contain any certificates
func NewPool(filename string) (*x509.CertPool, error) {
	pemBlock, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	pool, err := NewPoolFromBytes(pemBlock)
	if err != nil {
		return nil, fmt.Errorf("error creating pool from %s: %s", filename, err)
	}
	return pool, nil
}

// NewPoolFromBytes returns an x509.CertPool containing the certificates in the given PEM-encoded bytes.
// Returns an error if the file could not be read, a certificate could not be parsed, or if the file does not contain any certificates
func NewPoolFromBytes(pemBlock []byte) (*x509.CertPool, error) {
	certs, err := ParseCertsPEM(pemBlock)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool, nil
}

// CertsFromFile returns the x509.Certificates contained in the given PEM-encoded file.
// Returns an error if the file could not be read, a certificate could not be parsed, or if the file does not contain any certificates
func CertsFromFile(file string) ([]*x509.Certificate, error) {
	pemBlock, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	certs, err := ParseCertsPEM(pemBlock)
	if err != nil {
		return nil, fmt.Errorf("error reading %s: %s", file, err)
	}
	return certs, nil
}
