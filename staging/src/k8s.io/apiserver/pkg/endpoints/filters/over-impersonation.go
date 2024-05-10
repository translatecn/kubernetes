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

package filters

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"k8s.io/klog/v2"

	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/audit"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/handlers/responsewriters"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/server/httplog"
)

// WithImpersonation 是一个筛选器,它将检查和试图更改用户的请求
func WithImpersonation(handler http.Handler, a authorizer.Authorizer, s runtime.NegotiatedSerializer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		impersonationRequests, err := buildImpersonationRequests(req.Header)
		if err != nil {
			klog.V(4).Infof("%v", err)
			responsewriters.InternalError(w, req, err)
			return
		}
		if len(impersonationRequests) == 0 {
			handler.ServeHTTP(w, req)
			return
		}

		ctx := req.Context()
		requestor, exists := request.UserFrom(ctx)
		if !exists {
			responsewriters.InternalError(w, req, errors.New("no user found for request"))
			return
		}
		// 如果未指定组,则需要根据用户类型以不同的方式查找它们
		// 如果指定了组,则它们是权限机构 (including the inclusion of system:authenticated/system:unauthenticated groups)
		groupsSpecified := len(req.Header[authenticationv1.ImpersonateGroupHeader]) > 0

		// 确保我们有权模拟我们请求的每个对象.在我们遍历时,开始构建用户名和组信息.
		username := ""
		groups := []string{}
		userExtra := map[string][]string{}
		uid := ""
		for _, impersonationRequest := range impersonationRequests {
			gvk := impersonationRequest.GetObjectKind().GroupVersionKind()
			actingAsAttributes := &authorizer.AttributesRecord{
				User:            requestor,
				Verb:            "impersonate",
				APIGroup:        gvk.Group,
				APIVersion:      gvk.Version,
				Namespace:       impersonationRequest.Namespace,
				Name:            impersonationRequest.Name,
				ResourceRequest: true,
			}

			switch gvk.GroupKind() {
			case v1.SchemeGroupVersion.WithKind("ServiceAccount").GroupKind():
				actingAsAttributes.Resource = "serviceaccounts"
				username = serviceaccount.MakeUsername(impersonationRequest.Namespace, impersonationRequest.Name)
				if !groupsSpecified {
					// if groups aren't specified for a service account, we know the groups because its a fixed mapping.  Add them
					groups = serviceaccount.MakeGroupNames(impersonationRequest.Namespace)
				}

			case v1.SchemeGroupVersion.WithKind("User").GroupKind():
				actingAsAttributes.Resource = "users"
				username = impersonationRequest.Name

			case v1.SchemeGroupVersion.WithKind("Group").GroupKind():
				actingAsAttributes.Resource = "groups"
				groups = append(groups, impersonationRequest.Name)

			case authenticationv1.SchemeGroupVersion.WithKind("UserExtra").GroupKind():
				extraKey := impersonationRequest.FieldPath
				extraValue := impersonationRequest.Name
				actingAsAttributes.Resource = "userextras"
				actingAsAttributes.Subresource = extraKey
				userExtra[extraKey] = append(userExtra[extraKey], extraValue)

			case authenticationv1.SchemeGroupVersion.WithKind("UID").GroupKind():
				uid = string(impersonationRequest.Name)
				actingAsAttributes.Resource = "uids"

			default:
				klog.V(4).InfoS("unknown impersonation request type", "Request", impersonationRequest)
				responsewriters.Forbidden(ctx, actingAsAttributes, w, req, fmt.Sprintf("unknown impersonation request type: %v", impersonationRequest), s)
				return
			}

			decision, reason, err := a.Authorize(ctx, actingAsAttributes)
			if err != nil || decision != authorizer.DecisionAllow {
				klog.V(4).InfoS("Forbidden", "URI", req.RequestURI, "Reason", reason, "Error", err)
				responsewriters.Forbidden(ctx, actingAsAttributes, w, req, reason, s)
				return
			}
		}

		if username != user.Anonymous { // system:anonymous
			// When impersonating a non-anonymous user, include the 'system:authenticated' group
			// in the impersonated user info:
			// - if no groups were specified
			// - if a group has been specified other than 'system:authenticated'
			//
			// If 'system:unauthenticated' group has been specified we should not include
			// the 'system:authenticated' group.
			addAuthenticated := true
			for _, group := range groups {
				if group == user.AllAuthenticated || group == user.AllUnauthenticated {
					addAuthenticated = false
					break
				}
			}

			if addAuthenticated {
				groups = append(groups, user.AllAuthenticated)
			}
		} else {
			addUnauthenticated := true
			for _, group := range groups {
				if group == user.AllUnauthenticated {
					addUnauthenticated = false
					break
				}
			}

			if addUnauthenticated {
				groups = append(groups, user.AllUnauthenticated)
			}
		}

		newUser := &user.DefaultInfo{
			Name:   username,
			Groups: groups,
			Extra:  userExtra,
			UID:    uid,
		}
		req = req.WithContext(request.WithUser(ctx, newUser))

		oldUser, _ := request.UserFrom(ctx)
		httplog.LogOf(req, w).Addf("%v is acting as %v", oldUser, newUser)

		ae := audit.AuditEventFrom(ctx)
		audit.LogImpersonatedUser(ae, newUser)

		// clear all the impersonation headers from the request
		req.Header.Del(authenticationv1.ImpersonateUserHeader)
		req.Header.Del(authenticationv1.ImpersonateGroupHeader)
		req.Header.Del(authenticationv1.ImpersonateUIDHeader)
		for headerName := range req.Header {
			if strings.HasPrefix(headerName, authenticationv1.ImpersonateUserExtraHeaderPrefix) {
				req.Header.Del(headerName)
			}
		}

		handler.ServeHTTP(w, req)
	})
}

func unescapeExtraKey(encodedKey string) string {
	key, err := url.PathUnescape(encodedKey) // Decode %-encoded bytes.
	if err != nil {
		return encodedKey // Always record extra strings, even if malformed/unencoded.
	}
	return key
}

// buildImpersonationRequests 返回一个对象引用列表,表示我们要模拟的不同对象.
// 还包括一个表示user.Info.Extra的map[string][]string
// 在切换上下文之前,必须对每个请求进行当前用户的授权.
func buildImpersonationRequests(headers http.Header) ([]v1.ObjectReference, error) {
	impersonationRequests := []v1.ObjectReference{}

	requestedUser := headers.Get(authenticationv1.ImpersonateUserHeader)
	hasUser := len(requestedUser) > 0
	if hasUser {
		if namespace, name, err := serviceaccount.SplitUsername(requestedUser); err == nil {
			impersonationRequests = append(impersonationRequests, v1.ObjectReference{Kind: "ServiceAccount", Namespace: namespace, Name: name})
		} else {
			impersonationRequests = append(impersonationRequests, v1.ObjectReference{Kind: "User", Name: requestedUser})
		}
	}

	hasGroups := false
	for _, group := range headers[authenticationv1.ImpersonateGroupHeader] { // Impersonate-Group
		hasGroups = true
		impersonationRequests = append(impersonationRequests, v1.ObjectReference{Kind: "Group", Name: group})
	}

	hasUserExtra := false
	for headerName, values := range headers {
		if !strings.HasPrefix(headerName, authenticationv1.ImpersonateUserExtraHeaderPrefix) { // Impersonate-Extra-
			continue
		}

		hasUserExtra = true
		extraKey := unescapeExtraKey(strings.ToLower(headerName[len(authenticationv1.ImpersonateUserExtraHeaderPrefix):]))

		// 为他们试图设置的每个额外值提出单独的请求
		for _, value := range values {
			impersonationRequests = append(impersonationRequests,
				v1.ObjectReference{
					Kind: "UserExtra",
					// we only parse out a group above, but the parsing will fail if there isn't SOME version
					// using the internal version will help us fail if anyone starts using it
					APIVersion: authenticationv1.SchemeGroupVersion.String(),
					Name:       value,
					// ObjectReference doesn't have a subresource field.  FieldPath is close and available, so we'll use that
					// TODO fight the good fight for ObjectReference to refer to resources and subresources
					FieldPath: extraKey,
				})
		}
	}

	requestedUID := headers.Get(authenticationv1.ImpersonateUIDHeader) // Impersonate-Uid
	hasUID := len(requestedUID) > 0
	if hasUID {
		impersonationRequests = append(impersonationRequests, v1.ObjectReference{
			Kind:       "UID",
			Name:       requestedUID,
			APIVersion: authenticationv1.SchemeGroupVersion.String(),
		})
	}

	if (hasGroups || hasUserExtra || hasUID) && !hasUser {
		return nil, fmt.Errorf("requested %v without impersonating a user", impersonationRequests)
	}

	return impersonationRequests, nil
}
