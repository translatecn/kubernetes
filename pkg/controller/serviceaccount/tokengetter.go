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

package serviceaccount

import (
	"context"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	v1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/kubernetes/pkg/serviceaccount"
)

type clientGetter struct {
	client               clientset.Interface
	secretLister         v1listers.SecretLister
	serviceAccountLister v1listers.ServiceAccountLister
	podLister            v1listers.PodLister
}

// NewGetterFromClient 返回一个ServiceAccountTokenGetter，它使用指定的客户端来检索服务帐户和秘密。
// 客户端不应该使用返回的getter将用于检索的服务帐户令牌进行身份验证，否则将导致递归。
func NewGetterFromClient(c clientset.Interface, secretLister v1listers.SecretLister, serviceAccountLister v1listers.ServiceAccountLister, podLister v1listers.PodLister) serviceaccount.ServiceAccountTokenGetter {
	return clientGetter{c, secretLister, serviceAccountLister, podLister}
}

func (c clientGetter) GetServiceAccount(namespace, name string) (*v1.ServiceAccount, error) {
	if serviceAccount, err := c.serviceAccountLister.ServiceAccounts(namespace).Get(name); err == nil { // 从缓存读
		return serviceAccount, nil
	}
	return c.client.CoreV1().ServiceAccounts(namespace).Get(context.TODO(), name, metav1.GetOptions{}) // 从接口读
}

func (c clientGetter) GetPod(namespace, name string) (*v1.Pod, error) {
	if pod, err := c.podLister.Pods(namespace).Get(name); err == nil {
		return pod, nil
	}
	return c.client.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

func (c clientGetter) GetSecret(namespace, name string) (*v1.Secret, error) {
	if secret, err := c.secretLister.Secrets(namespace).Get(name); err == nil {
		return secret, nil
	}
	return c.client.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}
