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
	"net/http"

	"k8s.io/apimachinery/pkg/types"
	auditinternal "k8s.io/apiserver/pkg/apis/audit"
	"k8s.io/apiserver/pkg/audit"

	"github.com/google/uuid"
)

// WithAuditInit 初始化审核上下文并附加与请求关联的Audit-ID。
// a. 如果调用者没有在请求标头中指定Audit-ID的值，则我们会生成新的审核ID
// b. 我们通过响应标头“Audit-ID”向调用者回显Audit-ID值。
func WithAuditInit(handler http.Handler) http.Handler {
	return withAuditInit(handler, func() string {
		return uuid.New().String()
	})
}

func withAuditInit(handler http.Handler, newAuditIDFunc func() string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := audit.WithAuditContext(r.Context()) // 允许审计
		r = r.WithContext(ctx)

		auditID := r.Header.Get(auditinternal.HeaderAuditID)
		if len(auditID) == 0 {
			auditID = newAuditIDFunc()
		}

		// Note: 我们保存用户指定的Audit-ID标头值，不执行截断。
		audit.WithAuditID(ctx, types.UID(auditID))

		// 我们将Audit-ID回显到响应标头中。
		// 并不是所有请求都保证发送Audit-ID http标头。
		// 例如，当用户运行“kubectl exec”时，apiserver 使用代理处理程序来处理请求，用户只能获取由kubelet节点返回的http标头。
		// 此过滤器也将用于其他聚合的api服务器。对于聚合API我们不希望看到相同的审核ID出现超过一次。
		if value := w.Header().Get(auditinternal.HeaderAuditID); len(value) == 0 {
			w.Header().Set(auditinternal.HeaderAuditID, auditID)
		}

		handler.ServeHTTP(w, r)
	})
}
