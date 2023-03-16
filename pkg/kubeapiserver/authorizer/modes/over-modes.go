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

package modes

import "k8s.io/apimachinery/pkg/util/sets"

const (
	ModeAlwaysAllow string = "AlwaysAllow" // 是否将所有请求设置为授权模式
	ModeAlwaysDeny  string = "AlwaysDeny"  // 是否将所有请求设置为无授权模式
	ModeABAC        string = "ABAC"        // 是否使用基于属性的访问控制进行授权
	ModeWebhook     string = "Webhook"     // 外部webhook调用模式是否授权
	ModeRBAC        string = "RBAC"        // 是否使用基于角色的访问控制进行授权
	ModeNode        string = "Node"        // 是一种授权模式,用于授权kubelets发出的API请求.
)

// AuthorizationModeChoices is the list of supported authorization modes
var AuthorizationModeChoices = []string{ModeAlwaysAllow, ModeAlwaysDeny, ModeABAC, ModeWebhook, ModeRBAC, ModeNode}

// IsValidAuthorizationMode returns true if the given authorization mode is a valid one for the apiserver
func IsValidAuthorizationMode(authzMode string) bool {
	return sets.NewString(AuthorizationModeChoices...).Has(authzMode)
}
