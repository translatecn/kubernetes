/*
Copyright 2021 The Kubernetes Authors.

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

package filters

import (
	"context"
	"net/http"
)

type muxAndDiscoveryIncompleteKeyType int

const (
	// muxAndDiscoveryIncompleteKey 在服务器安装所有已知HTTP路径之前发出的所有请求的保护信号存储在请求的上下文中的键是什么
	muxAndDiscoveryIncompleteKey muxAndDiscoveryIncompleteKeyType = iota
)

// NoMuxAndDiscoveryIncompleteKey 检查上下文是否包含muxAndDiscoveryIncompleteKey。当HTTP路径未安装时，该键表示已经发出请求。
func NoMuxAndDiscoveryIncompleteKey(ctx context.Context) bool { // 没有Mux和发现不完整的键
	muxAndDiscoveryCompleteProtectionKeyValue, _ := ctx.Value(muxAndDiscoveryIncompleteKey).(string)
	return len(muxAndDiscoveryCompleteProtectionKeyValue) == 0
}

// WithMuxAndDiscoveryComplete puts the muxAndDiscoveryIncompleteKey in the context if a request has been made before muxAndDiscoveryCompleteSignal has been ready.
// Putting the key protect us from returning a 404 response instead of a 503.
// It is especially important for controllers like GC and NS since they act on 404s.
//
// The presence of the key is checked in the NotFoundHandler (staging/src/k8s.io/apiserver/pkg/util/notfoundhandler/not_found_handler.go)
//
// The primary reason this filter exists is to protect from a potential race between the client's requests reaching the NotFoundHandler and the server becoming ready.
// Without the protection key a request could still get a 404 response when the registered signals changed their status just slightly before reaching the new handler.
// In that case, the presence of the key will make the handler return a 503 instead of a 404.
func WithMuxAndDiscoveryComplete(handler http.Handler, muxAndDiscoveryCompleteSignal <-chan struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if muxAndDiscoveryCompleteSignal != nil && !isClosed(muxAndDiscoveryCompleteSignal) {
			req = req.WithContext(context.WithValue(req.Context(), muxAndDiscoveryIncompleteKey, "MuxAndDiscoveryInstallationNotComplete"))
		}
		handler.ServeHTTP(w, req)
	})
}

// isClosed is a convenience function that simply check if the given chan has been closed
func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
