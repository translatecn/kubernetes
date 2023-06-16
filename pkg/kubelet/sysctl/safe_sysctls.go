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

package sysctl

// https://blog.51cto.com/u_11979904/5675931

// SafeSysctlAllowlist returns the allowlist of safe sysctls and safe sysctl patterns (ending in *).
//
// A sysctl is called safe iff
// - it is namespaced in the container or the pod
// - it is isolated, i.e. has no influence on any other pod on the same node.
// 当且仅当 sysctl
// - 它在容器或 Pod 中具有 命名空间
// - 它是隔离的,即对同一节点上的任何其他 Pod 没有影响时,sysctl 被称为安全.
func SafeSysctlAllowlist() []string {
	return []string{
		"kernel.shm_rmid_forced",              // =1 表示是否强制将共享内存和一个进程联系在一起,这样的话可以通过杀死进程来释放共享内存
		"net.ipv4.ip_local_port_range",        // 表示允许使用的端口范围
		"net.ipv4.tcp_syncookies",             // 是否打开SYN Cookie功能 ,防止syn 攻击
		"net.ipv4.ping_group_range",           // 允许使用ICMP套接字的组ID的范围,默认值为1 0
		"net.ipv4.ip_unprivileged_port_start", // 是命名空间粒度的配置,定义了非特权端口的最小值.特权端口需要root或 CAP_NET_BIND_SERVICE 才能绑定.默认值为1024.
	}
}
