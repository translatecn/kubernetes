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

// NoMuxAndDiscoveryIncompleteKey 检查上下文是否包含muxAndDiscoveryIncompleteKey.当HTTP路径未安装时,该键表示已经发出请求.
func NoMuxAndDiscoveryIncompleteKey(ctx context.Context) bool { // 没有Mux和发现不完整的键
	muxAndDiscoveryCompleteProtectionKeyValue, _ := ctx.Value(muxAndDiscoveryIncompleteKey).(string)
	return len(muxAndDiscoveryCompleteProtectionKeyValue) == 0
}

// WithMuxAndDiscoveryComplete 如果在muxAndDiscoveryCompleteSignal准备好之前进行了请求,则将muxAndDiscoveryIncompleteKey放入上下文中.
// 放置 muxAndDiscoveryIncompleteKey 保护我们免受返回404响应而不是503的影响.
// 对于像GC和NS这样的控制器尤其重要,因为它们会对404进行操作.
// 在NotFoundHandler（staging/src/k8s.io/apiserver/pkg/util/notfoundhandler/not_found_handler.go）中检查muxAndDiscoveryIncompleteKey的存在
// 此过滤器存在的主要原因是保护免受客户端请求到达NotFoundHandler和服务器变为就绪之间的潜在竞争的影响.
// 如果没有保护密钥,则请求仍可能在注册的信号在到达新处理程序之前略微更改其状态时收到404响应.
// 在这种情况下,密钥的存在将使处理程序返回503而不是404.
func WithMuxAndDiscoveryComplete(handler http.Handler, muxAndDiscoveryCompleteSignal <-chan struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if muxAndDiscoveryCompleteSignal != nil && !isClosed(muxAndDiscoveryCompleteSignal) {
			req = req.WithContext(context.WithValue(req.Context(), muxAndDiscoveryIncompleteKey, "MuxAndDiscoveryInstallationNotComplete"))
		}
		handler.ServeHTTP(w, req)
	})
}

// isClosed 这是一个方便的函数,仅检查给定的通道是否已关闭.
func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
