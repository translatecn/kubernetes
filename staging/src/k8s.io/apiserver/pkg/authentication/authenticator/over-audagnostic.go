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

import (
	"context"
	"fmt"
	"net/http"
)

func authenticate(ctx context.Context, implicitAuds Audiences, authenticate func() (*Response, bool, error)) (*Response, bool, error) {
	targetAuds, ok := AudiencesFrom(ctx)
	//一旦api audience不为空,我们就可以删除它.在TokenRequest是GA之后,可能会有N个发布.
	if !ok {
		return authenticate()
	}
	auds := implicitAuds.Intersect(targetAuds)
	if len(auds) == 0 {
		return nil, false, nil
	}
	resp, ok, err := authenticate()
	if err != nil || !ok {
		return nil, false, err
	}
	if len(resp.Audiences) > 0 {
		// maybe the authenticator was audience aware after all.
		return nil, false, fmt.Errorf("与受众无关的验证器包装了一个返回受众的验证器: %q", resp.Audiences)
	}
	resp.Audiences = auds
	return resp, true, nil
}

type audAgnosticRequestAuthenticator struct {
	implicit Audiences // 命令行 指定的用户
	delegate Request   // token csv文件存在的用户
}

var _ = Request(&audAgnosticRequestAuthenticator{})

func (a *audAgnosticRequestAuthenticator) AuthenticateRequest(req *http.Request) (*Response, bool, error) {
	return authenticate(req.Context(), a.implicit, func() (*Response, bool, error) {
		return a.delegate.AuthenticateRequest(req)
	})
}

// WrapAudienceAgnosticRequest 将面向受众不可知的请求认证器包装起来,以将其接受的受众限制为一组隐式受众.
func WrapAudienceAgnosticRequest(implicit Audiences, delegate Request) Request {
	return &audAgnosticRequestAuthenticator{
		implicit: implicit,
		delegate: delegate,
	}
}

// ----------------------------------------------------------------------------------------

type AudAgnosticTokenAuthenticator struct {
	implicit Audiences // [https://kubernetes.default.svc.cluster.local]
	delegate Token
}

var _ = Token(&AudAgnosticTokenAuthenticator{})

func (a *AudAgnosticTokenAuthenticator) AuthenticateToken(ctx context.Context, tok string) (*Response, bool, error) {
	return authenticate(ctx, a.implicit, func() (*Response, bool, error) {
		return a.delegate.AuthenticateToken(ctx, tok)
	})
}

func WrapAudienceAgnosticToken(implicit Audiences, delegate Token) Token {
	return &AudAgnosticTokenAuthenticator{
		implicit: implicit,
		delegate: delegate,
	}
}
