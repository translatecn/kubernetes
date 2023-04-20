/*
Copyright 2017 The Kubernetes Authors.

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

package union

import (
	"context"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/authentication/authenticator"
)

// UnionAuthTokenHandler 使用验证器链验证令牌.令牌对象
type UnionAuthTokenHandler struct {
	Handlers    []authenticator.Token
	FailOnError bool // 确定错误返回是否会使链短路
}

func New(authTokenHandlers ...authenticator.Token) authenticator.Token {
	if len(authTokenHandlers) == 1 {
		return authTokenHandlers[0]
	}
	return &UnionAuthTokenHandler{Handlers: authTokenHandlers, FailOnError: false}
}

func NewFailOnError(authTokenHandlers ...authenticator.Token) authenticator.Token {
	if len(authTokenHandlers) == 1 {
		return authTokenHandlers[0]
	}
	return &UnionAuthTokenHandler{Handlers: authTokenHandlers, FailOnError: true}
}

// AuthenticateToken 使用验证器链对令牌进行身份验证.令牌对象.
func (authHandler *UnionAuthTokenHandler) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	var errlist []error
	for _, currAuthRequestHandler := range authHandler.Handlers {
		info, ok, err := currAuthRequestHandler.AuthenticateToken(ctx, token)
		if err != nil {
			if authHandler.FailOnError {
				return info, ok, err
			}
			errlist = append(errlist, err)
			continue
		}

		if ok {
			return info, ok, err
		}
	}

	return nil, false, utilerrors.NewAggregate(errlist)
}
