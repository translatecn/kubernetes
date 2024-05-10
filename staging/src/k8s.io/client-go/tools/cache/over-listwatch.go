/*
Copyright 2015 The Kubernetes Authors.

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

package cache

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	restclient "k8s.io/client-go/rest"
)

type Lister interface {
	List(options metav1.ListOptions) (runtime.Object, error)
}

type Watcher interface {
	Watch(options metav1.ListOptions) (watch.Interface, error)
}

type ListerWatcher interface {
	Lister
	Watcher
}

type ListFunc func(options metav1.ListOptions) (runtime.Object, error)

type WatchFunc func(options metav1.ListOptions) (watch.Interface, error)

type ListWatch struct {
	ListFunc        ListFunc
	WatchFunc       WatchFunc
	DisableChunking bool // 禁止分片
}

// Getter interface knows how to access Get method from RESTClient.
type Getter interface {
	Get() *restclient.Request
}

// NewListWatchFromClient creates a new ListWatch from the specified client, resource, namespace and field selector.
func NewListWatchFromClient(c Getter, resource string, namespace string, fieldSelector fields.Selector) *ListWatch {
	optionsModifier := func(options *metav1.ListOptions) {
		options.FieldSelector = fieldSelector.String() // 序列化成字符串
	}
	return NewFilteredListWatchFromClient(c, resource, namespace, optionsModifier)
}

func NewFilteredListWatchFromClient(c Getter, resource string, namespace string, optionsModifier func(options *metav1.ListOptions)) *ListWatch {
	listFunc := func(options metav1.ListOptions) (runtime.Object, error) {
		optionsModifier(&options)
		return c.Get(). // 其实就是RESTClient.Get(）,返回的是*rest.Request对象
				Namespace(namespace).
				Resource(resource).
				VersionedParams(&options, metav1.ParameterCodec).
				Do(context.TODO()).
				Get()
	}
	watchFunc := func(options metav1.ListOptions) (watch.Interface, error) {
		options.Watch = true
		optionsModifier(&options)
		return c.Get(). // 其实就是RESTClient.Get(）,返回的是*rest.Request对象
				Namespace(namespace).
				Resource(resource).
				VersionedParams(&options, metav1.ParameterCodec).
				Watch(context.TODO())
	}
	return &ListWatch{ListFunc: listFunc, WatchFunc: watchFunc}
}

// List a set of apiserver resources
func (lw *ListWatch) List(options metav1.ListOptions) (runtime.Object, error) {
	// ListWatch is used in Reflector, which already supports pagination.
	// Don't paginate here to avoid duplication.
	return lw.ListFunc(options)
}

// Watch a set of apiserver resources
func (lw *ListWatch) Watch(options metav1.ListOptions) (watch.Interface, error) {
	return lw.WatchFunc(options)
}
