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

package group

import (
	"net/http"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

// AuthenticatedGroupAdder adds system:authenticated group when appropriate
type AuthenticatedGroupAdder struct {
	Authenticator authenticator.Request
}

// NewAuthenticatedGroupAdder 包装一个请求认证器,并在适当时添加system:authenticated组.
// 认证必须成功,用户不能是system:anonymous,组system:authenticated或system:unauthenticated不能存在.
func NewAuthenticatedGroupAdder(auth authenticator.Request) authenticator.Request {
	return &AuthenticatedGroupAdder{auth}
}

func (g *AuthenticatedGroupAdder) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	r, ok, err := g.Authenticator.AuthenticateRequest(req)
	if err != nil || !ok {
		return nil, ok, err
	}

	if r.User.GetName() == user.Anonymous {
		return r, true, nil
	}
	for _, group := range r.User.GetGroups() {
		if group == user.AllAuthenticated || group == user.AllUnauthenticated {
			return r, true, nil
		}
	}

	newGroups := make([]string, 0, len(r.User.GetGroups())+1)
	newGroups = append(newGroups, r.User.GetGroups()...)
	newGroups = append(newGroups, user.AllAuthenticated)

	ret := *r // 浅拷贝
	ret.User = &user.DefaultInfo{
		Name:   r.User.GetName(),
		UID:    r.User.GetUID(),
		Groups: newGroups,
		Extra:  r.User.GetExtra(),
	}
	return &ret, true, nil
}
