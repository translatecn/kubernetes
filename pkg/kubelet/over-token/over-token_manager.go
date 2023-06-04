/*
Copyright 2018 The Kubernetes Authors.

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

// Package token implements a manager of serviceaccount tokens for pods running
// on the node.
package over_token

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
)

const (
	maxTTL    = 24 * time.Hour
	gcPeriod  = time.Minute
	maxJitter = 10 * time.Second
)

// NewManager returns a new token manager.
func NewManager(c clientset.Interface) *Manager {
	// check whether the server supports token requests so we can give a more helpful error message
	supported := false
	once := &sync.Once{}
	tokenRequestsSupported := func() bool {
		once.Do(func() {
			resources, err := c.Discovery().ServerResourcesForGroupVersion("v1")
			if err != nil {
				return
			}
			for _, resource := range resources.APIResources {
				if resource.Name == "serviceaccounts/token" {
					supported = true
					return
				}
			}
		})
		return supported
	}

	m := &Manager{
		getToken: func(name, namespace string, tr *authenticationv1.TokenRequest) (*authenticationv1.TokenRequest, error) {
			if c == nil {
				return nil, errors.New("cannot use TokenManager when kubelet is in standalone mode")
			}
			tokenRequest, err := c.CoreV1().ServiceAccounts(namespace).CreateToken(context.TODO(), name, tr, metav1.CreateOptions{})
			if apierrors.IsNotFound(err) && !tokenRequestsSupported() {
				return nil, fmt.Errorf("the API server does not have TokenRequest endpoints enabled")
			}
			return tokenRequest, err
		},
		cache: make(map[string]*authenticationv1.TokenRequest),
		clock: clock.RealClock{},
	}
	go wait.Forever(m.cleanup, gcPeriod)
	return m
}

// Manager manages service account tokens for pods.
type Manager struct {

	// cacheMutex guards the cache
	cacheMutex sync.RWMutex
	cache      map[string]*authenticationv1.TokenRequest

	// mocked for testing
	getToken func(name, namespace string, tr *authenticationv1.TokenRequest) (*authenticationv1.TokenRequest, error)
	clock    clock.Clock
}

// DeleteServiceAccountToken should be invoked when pod got deleted. It simply
// clean token manager cache.
func (m *Manager) DeleteServiceAccountToken(podUID types.UID) {
	m.cacheMutex.Lock()
	defer m.cacheMutex.Unlock()
	for k, tr := range m.cache {
		if tr.Spec.BoundObjectRef.UID == podUID {
			delete(m.cache, k)
		}
	}
}

func (m *Manager) cleanup() {
	m.cacheMutex.Lock()
	defer m.cacheMutex.Unlock()
	for k, tr := range m.cache {
		if m.expired(tr) {
			delete(m.cache, k)
		}
	}
}

// keys should be nonconfidential and safe to log
func keyFunc(name, namespace string, tr *authenticationv1.TokenRequest) string {
	var exp int64
	if tr.Spec.ExpirationSeconds != nil {
		exp = *tr.Spec.ExpirationSeconds
	}

	var ref authenticationv1.BoundObjectReference
	if tr.Spec.BoundObjectRef != nil {
		ref = *tr.Spec.BoundObjectRef
	}

	return fmt.Sprintf("%q/%q/%#v/%#v/%#v", name, namespace, tr.Spec.Audiences, exp, ref)
}

// GetServiceAccountToken 这段代码实现了从缓存或 TokenRequest API 获取服务账号令牌的逻辑,并且包含了以下几个步骤：
//
// 1. 检查缓存中是否存在当前令牌请求.
// 2. 如果令牌存在并且不需要刷新,则返回当前令牌.
// 3. 尝试刷新令牌.
// 4. 如果令牌刷新成功,则将其保存在缓存中并返回令牌.
// 5. 如果刷新失败并且旧令牌仍然有效,则记录错误并返回旧令牌.
// 6. 如果刷新失败并且旧令牌不再有效,则返回错误.
//
// 具体实现细节可能需要查看代码.
func (m *Manager) GetServiceAccountToken(namespace, name string, tr *authenticationv1.TokenRequest) (*authenticationv1.TokenRequest, error) {
	key := keyFunc(name, namespace, tr)

	ctr, ok := m.get(key)

	if ok && !m.requiresRefresh(ctr) {
		return ctr, nil
	}

	tr, err := m.getToken(name, namespace, tr)
	if err != nil {
		switch {
		case !ok:
			return nil, fmt.Errorf("failed to fetch token: %v", err)
		case m.expired(ctr):
			return nil, fmt.Errorf("token %s expired and refresh failed: %v", key, err)
		default:
			klog.ErrorS(err, "Couldn't update token", "cacheKey", key)
			return ctr, nil
		}
	}

	m.set(key, tr)
	return tr, nil
}
func (m *Manager) requiresRefresh(tr *authenticationv1.TokenRequest) bool {
	if tr.Spec.ExpirationSeconds == nil {
		cpy := tr.DeepCopy()
		cpy.Status.Token = ""
		klog.ErrorS(nil, "Expiration seconds was nil for token request", "tokenRequest", cpy)
		return false
	}
	now := m.clock.Now()
	exp := tr.Status.ExpirationTimestamp.Time
	iat := exp.Add(-1 * time.Duration(*tr.Spec.ExpirationSeconds) * time.Second) // 过期时间 - 有效期的期望持续时间 = 签发时间

	jitter := time.Duration(rand.Float64()*maxJitter.Seconds()) * time.Second
	// 如果令牌的年龄超过其总ttl的80％,或者令牌的年龄超过24小时,则requiresRefresh返回true.
	if now.After(iat.Add(maxTTL - jitter)) { // 24小时,
		return true
	}
	// Require a refresh if within 20% of the TTL plus a jitter from the expiration time.
	if now.After(exp.Add(-1*time.Duration((*tr.Spec.ExpirationSeconds*20)/100)*time.Second - jitter)) { // 一般 token 是一个小时,也就是颁发50分钟后,就会重新请求
		return true
	}
	return false
}

func (m *Manager) get(key string) (*authenticationv1.TokenRequest, bool) {
	m.cacheMutex.RLock()
	defer m.cacheMutex.RUnlock()
	ctr, ok := m.cache[key]
	return ctr, ok
}

func (m *Manager) set(key string, tr *authenticationv1.TokenRequest) {
	m.cacheMutex.Lock()
	defer m.cacheMutex.Unlock()
	m.cache[key] = tr
}

func (m *Manager) expired(t *authenticationv1.TokenRequest) bool {
	return m.clock.Now().After(t.Status.ExpirationTimestamp.Time)
}
