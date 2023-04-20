/*
Copyright 2015 The Kubernetes Authors.

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

import (
	"os"
	"path"
	"strconv"
	"strings"
)

const (
	sysctlBase = "/proc/sys" // 是 sysctl 变量的基本路径

	VMOvercommitMemory = "vm/overcommit_memory"      // 是负责定义内核使用的内存超额提交策略的 sysctl 变量。
	VMPanicOnOOM       = "vm/panic_on_oom"           // 是负责定义内核使用的 OOM 行为的 sysctl 变量。
	KernelPanic        = "kernel/panic"              // 是负责定义内核在崩溃后重新启动的超时时间的 sysctl 变量。
	KernelPanicOnOops  = "kernel/panic_on_oops"      // 是负责定义内核在遇到 oops 或 BUG 时的行为的 sysctl 变量。
	RootMaxKeys        = "kernel/keys/root_maxkeys"  // 是负责定义 root 用户（在 root 用户命名空间中的 UID 0）可以拥有的最大密钥数的 sysctl 变量。
	RootMaxBytes       = "kernel/keys/root_maxbytes" // 是负责定义 root 用户（在 root 用户命名空间中的 UID 0）可以在拥有的密钥的负载中持有的最大数据字节数的 sysctl 变量。

	VMOvercommitMemoryAlways    = 1                       // 表示内核不执行内存超额提交处理。
	VMPanicOnOOMInvokeOOMKiller = 0                       // 表示内核在发生 OOM 时调用 oom_killer 函数。
	KernelPanicOnOopsAlways     = 1                       // 表示内核在发生 kernel oops 时崩溃。
	KernelPanicRebootTimeout    = 10                      // 是内核在崩溃后重新启动的超时时间。
	RootMaxKeysSetting          = 1000000                 // 是 root 用户（在 root 用户命名空间中的 UID 0）可以拥有的最大密钥数的设置值。
	RootMaxBytesSetting         = RootMaxKeysSetting * 25 // 是 root 用户（在 root 用户命名空间中的 UID 0）可以在拥有的密钥的负载中持有的最大数据字节数的设置值。
)

type Interface interface {
	GetSysctl(sysctl string) (int, error)
	SetSysctl(sysctl string, newVal int) error
}

// New returns a new Interface for accessing sysctl
func New() Interface {
	return &procSysctl{}
}

// procSysctl implements Interface by reading and writing files under /proc/sys
type procSysctl struct {
}

// GetSysctl returns the value for the specified sysctl setting
func (*procSysctl) GetSysctl(sysctl string) (int, error) {
	data, err := os.ReadFile(path.Join(sysctlBase, sysctl))
	if err != nil {
		return -1, err
	}
	val, err := strconv.Atoi(strings.Trim(string(data), " \n"))
	if err != nil {
		return -1, err
	}
	return val, nil
}

// SetSysctl modifies the specified sysctl flag to the new value
func (*procSysctl) SetSysctl(sysctl string, newVal int) error {
	return os.WriteFile(path.Join(sysctlBase, sysctl), []byte(strconv.Itoa(newVal)), 0640)
}
