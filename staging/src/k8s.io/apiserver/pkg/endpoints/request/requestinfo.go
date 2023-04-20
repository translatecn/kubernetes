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

package request

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"k8s.io/apimachinery/pkg/api/validation/path"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metainternalversionscheme "k8s.io/apimachinery/pkg/apis/meta/internalversion/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"k8s.io/klog/v2"
)

// LongRunningRequestCheck is a predicate which is true for long-running http requests.
type LongRunningRequestCheck func(r *http.Request, requestInfo *RequestInfo) bool

type RequestInfoResolver interface {
	NewRequestInfo(req *http.Request) (*RequestInfo, error)
}

// RequestInfo 保存从http.Request解析出的信息. ✅
type RequestInfo struct {
	// IsResourceRequest indicates whether or not the request is for an API resource or subresource
	IsResourceRequest bool
	// Path is the URL path of the request
	Path string
	// Verb is the kube verb associated with the request for API requests, not the http verb.  This includes things like list and watch.
	// for non-resource requests, this is the lowercase http verb
	Verb string

	APIPrefix  string
	APIGroup   string
	APIVersion string
	Namespace  string
	// Resource is the name of the resource being requested.  This is not the kind.  For example: pods
	Resource string
	// Subresource is the name of the subresource being requested.  This is a different resource, scoped to the parent resource, but it may have a different kind.
	// For instance, /pods has the resource "pods" and the kind "Pod", while /pods/foo/status has the resource "pods", the sub resource "status", and the kind "Pod"
	// (because status operates on pods). The binding resource for a pod though may be /pods/foo/binding, which has resource "pods", subresource "binding", and kind "Binding".
	Subresource string
	// Name is empty for some verbs, but if the request directly indicates a name (not in body content) then this field is filled in.
	Name string
	// Parts are the path parts for the request, always starting with /{resource}/{name}
	Parts []string
}

// specialVerbs contains just strings which are used in REST paths for special actions that don't fall under the normal
// CRUDdy GET/POST/PUT/DELETE actions on REST objects.
// TODO: find a way to keep this up to date automatically.  Maybe dynamically populate list as handlers added to
// master's Mux.
var specialVerbs = sets.NewString("proxy", "watch")

// specialVerbsNoSubresources 包含不允许子资源的根动词.
var specialVerbsNoSubresources = sets.NewString("proxy")

// namespaceSubresources 包含命名空间的子资源. 此列表允许解析器区分命名空间子资源和命名空间资源.
var namespaceSubresources = sets.NewString("status", "finalize")

// NamespaceSubResourcesForTest exports namespaceSubresources for testing in pkg/controlplane/master_test.go, so we never drift
var NamespaceSubResourcesForTest = sets.NewString(namespaceSubresources.List()...)

type RequestInfoFactory struct {
	APIPrefixes          sets.String // 所有资源的前缀集合    没有前和尾 斜杠.
	GrouplessAPIPrefixes sets.String // 内置资源的前缀集合    没有前和尾 斜杠.
}

// NewRequestInfo TODO 编写针对swagger文档的集成测试,以测试RequestInfo并将行为与响应匹配
// NewRequestInfo返回http请求的信息.如果错误不为nil,则RequestInfo在失败之前尽可能地保留信息
// 它处理资源和非资源请求,并为每个请求填充所有相关信息.
// 有效输入:
// Resource paths
// /apis/{api-group}/{version}/namespaces
// /api/{version}/namespaces
// /api/{version}/namespaces/{namespace}
// /api/{version}/namespaces/{namespace}/{resource}
// /api/{version}/namespaces/{namespace}/{resource}/{resourceName}
// /api/{version}/{resource}
// /api/{version}/{resource}/{resourceName}
//
// 没有子资源的特殊动词:
// /api/{version}/proxy/{resource}/{resourceName}
// /api/{version}/proxy/namespaces/{namespace}/{resource}/{resourceName}
//
// 具有子资源的特殊动词:
// /api/{version}/watch/{resource}
// /api/{version}/watch/namespaces/{namespace}/{resource}
//
// NonResource paths
// /apis/{api-group}/{version}
// /apis/{api-group}
// /apis
// /api/{version}
// /api
// /healthz
// /
func (r *RequestInfoFactory) NewRequestInfo(req *http.Request) (*RequestInfo, error) {
	//
	requestInfo := RequestInfo{
		APIPrefix:         "", // api、apis
		APIGroup:          "",
		IsResourceRequest: false,
		Path:              req.URL.Path,
		Verb:              strings.ToLower(req.Method),
	}

	currentParts := splitPath(req.URL.Path)
	if len(currentParts) < 3 {
		// return a non-resource request
		return &requestInfo, nil
	}

	if !r.APIPrefixes.Has(currentParts[0]) { // api 、apis
		// return a non-resource request
		return &requestInfo, nil
	}
	requestInfo.APIPrefix = currentParts[0] //
	currentParts = currentParts[1:]
	if !r.GrouplessAPIPrefixes.Has(requestInfo.APIPrefix) {
		// apis 进来
		// 一个部分（APIPrefix）已经被使用,所以这实际上是“我们有四个部分吗？”
		if len(currentParts) < 3 {
			// 没有group、version
			// return a non-resource request
			return &requestInfo, nil
		}

		requestInfo.APIGroup = currentParts[0]
		currentParts = currentParts[1:]
	}

	requestInfo.IsResourceRequest = true
	requestInfo.APIVersion = currentParts[0]
	currentParts = currentParts[1:]

	// 处理特殊动词  proxy、watch
	if specialVerbs.Has(currentParts[0]) {
		if len(currentParts) < 2 {
			return &requestInfo, fmt.Errorf("无法从URL确定类型和命名空间. %v", req.URL)
		}

		requestInfo.Verb = currentParts[0]
		currentParts = currentParts[1:]

	} else {
		switch req.Method {
		case "POST":
			requestInfo.Verb = "create"
		case "GET", "HEAD":
			requestInfo.Verb = "get"
		case "PUT":
			requestInfo.Verb = "update"
		case "PATCH":
			requestInfo.Verb = "patch"
		case "DELETE":
			requestInfo.Verb = "delete"
		default:
			requestInfo.Verb = ""
		}
	}

	// URL forms: /namespaces/{namespace}/{kind}/*, 其中各部分被调整为相对于类型.
	if currentParts[0] == "namespaces" {
		if len(currentParts) > 1 {
			requestInfo.Namespace = currentParts[1]

			// 如果命名空间名称后面还有另一步,并且它不是已知的命名空间子资源,则将currentParts移动以将其作为自己的资源包含.
			if len(currentParts) > 2 && !namespaceSubresources.Has(currentParts[2]) {
				currentParts = currentParts[2:]
			}
		}
	} else {
		requestInfo.Namespace = metav1.NamespaceNone
	}

	// 解析成功,因此我们现在知道.Parts的正确值.
	requestInfo.Parts = currentParts

	// parts look like: resource/resourceName/subresource/other/stuff/we/don't/interpret
	switch {
	case len(requestInfo.Parts) >= 3 && !specialVerbsNoSubresources.Has(requestInfo.Verb):
		requestInfo.Subresource = requestInfo.Parts[2]
		fallthrough
	case len(requestInfo.Parts) >= 2:
		requestInfo.Name = requestInfo.Parts[1]
		fallthrough
	case len(requestInfo.Parts) >= 1:
		requestInfo.Resource = requestInfo.Parts[0]
	}

	// 如果请求中没有名称,并且我们认为它是get之前,则实际动词是列表或观看.
	if len(requestInfo.Name) == 0 && requestInfo.Verb == "get" {
		opts := metainternalversion.ListOptions{}
		if err := metainternalversionscheme.ParameterCodec.DecodeParameters(req.URL.Query(), metav1.SchemeGroupVersion, &opts); err != nil {
			// An error in parsing request will result in default to "list" and not setting "name" field.
			klog.ErrorS(err, "Couldn't parse request", "Request", req.URL.Query())
			// Reset opts to not rely on partial results from parsing.
			// However, if watch is set, let's report it.
			opts = metainternalversion.ListOptions{}
			if values := req.URL.Query()["watch"]; len(values) > 0 {
				switch strings.ToLower(values[0]) {
				case "false", "0":
				default:
					opts.Watch = true
				}
			}
		}

		if opts.Watch {
			requestInfo.Verb = "watch"
		} else {
			requestInfo.Verb = "list"
		}

		if opts.FieldSelector != nil {
			if name, ok := opts.FieldSelector.RequiresExactMatch("metadata.name"); ok {
				if len(path.IsValidPathSegmentName(name)) == 0 {
					requestInfo.Name = name
				}
			}
		}
	}
	// if there's no name on the request and we thought it was a delete before, then the actual verb is deletecollection
	if len(requestInfo.Name) == 0 && requestInfo.Verb == "delete" {
		requestInfo.Verb = "deletecollection"
	}

	return &requestInfo, nil
}

type requestInfoKeyType int

// requestInfoKey is the RequestInfo key for the context. It's of private type here. Because
// keys are interfaces and interfaces are equal when the type and the value is equal, this
// does not conflict with the keys defined in pkg/api.
const requestInfoKey requestInfoKeyType = iota

// WithRequestInfo returns a copy of parent in which the request info value is set
func WithRequestInfo(parent context.Context, info *RequestInfo) context.Context {
	return WithValue(parent, requestInfoKey, info)
}

// RequestInfoFrom returns the value of the RequestInfo key on the ctx
func RequestInfoFrom(ctx context.Context) (*RequestInfo, bool) {
	info, ok := ctx.Value(requestInfoKey).(*RequestInfo)
	return info, ok
}

// splitPath returns the segments for a URL path.
func splitPath(path string) []string {
	path = strings.Trim(path, "/")
	if path == "" {
		return []string{}
	}
	return strings.Split(path, "/")
}
