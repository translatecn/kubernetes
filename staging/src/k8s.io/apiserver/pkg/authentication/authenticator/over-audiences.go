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

package authenticator

import "context"

// Audiences 是一个标记的Audiences的容器.
type Audiences []string

type key int

const (
	// audiencesKey 是请求受众的上下文key
	audiencesKey key = iota
)

// WithAudiences 返回存储请求预期受众的上下文.
func WithAudiences(ctx context.Context, auds Audiences) context.Context {
	return context.WithValue(ctx, audiencesKey, auds)
}

// AudiencesFrom returns a request's expected audiences stored in the request context.
func AudiencesFrom(ctx context.Context) (Audiences, bool) {
	auds, ok := ctx.Value(audiencesKey).(Audiences)
	return auds, ok
}

// Has checks if Audiences contains a specific audiences.
func (a Audiences) Has(taud string) bool {
	for _, aud := range a {
		if aud == taud {
			return true
		}
	}
	return false
}

// Intersect 获取交集
func (a Audiences) Intersect(tauds Audiences) Audiences {
	selected := Audiences{}
	for _, taud := range tauds {
		if a.Has(taud) {
			selected = append(selected, taud)
		}
	}
	return selected
}
