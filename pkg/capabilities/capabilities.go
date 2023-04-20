/*
Copyright 2014 The Kubernetes Authors.

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

package capabilities

import (
	"sync"
)

// Capabilities 定义系统中可用的功能集.目前这些是全局的.
type Capabilities struct {
	AllowPrivileged                        bool              // 允许特权
	PrivilegedSources                      PrivilegedSources // Pod源,允许主机联网、共享主机IPC名称空间和共享主机PID名称空间等特权功能.
	PerConnectionBandwidthLimitBytesPerSec int64             // 限制每个连接的吞吐量(目前仅用于proxy, exec, attach)
}

// PrivilegedSources 定义pod源,允许对某些类型的功能发出特权请求,如主机联网、共享主机IPC命名空间和共享主机PID命名空间.
type PrivilegedSources struct {
	HostNetworkSources []string // 允许使用主机网络的pod源列表.
	HostPIDSources     []string // 允许使用主机pid命名空间的pod源列表.
	HostIPCSources     []string // 允许使用主机ipc的pod源列表.
}

var capInstance struct {
	once         sync.Once
	lock         sync.Mutex
	capabilities *Capabilities
}

func Initialize(c Capabilities) {
	capInstance.once.Do(func() {
		capInstance.capabilities = &c
	})
}

func Setup(allowPrivileged bool, perConnectionBytesPerSec int64) {
	Initialize(Capabilities{
		AllowPrivileged:                        allowPrivileged,
		PerConnectionBandwidthLimitBytesPerSec: perConnectionBytesPerSec,
	})
}

// SetForTests sets capabilities for tests.  Convenience method for testing.  This should only be called from tests.
func SetForTests(c Capabilities) {
	capInstance.lock.Lock()
	defer capInstance.lock.Unlock()
	capInstance.capabilities = &c
}

// Get 返回系统功能的只读副本.
func Get() Capabilities {
	capInstance.lock.Lock()
	defer capInstance.lock.Unlock()
	// This check prevents clobbering of capabilities that might've been set via SetForTests
	if capInstance.capabilities == nil {
		Initialize(Capabilities{
			AllowPrivileged: false,
			PrivilegedSources: PrivilegedSources{
				HostNetworkSources: []string{},
				HostPIDSources:     []string{},
				HostIPCSources:     []string{},
			},
		})
	}
	return *capInstance.capabilities
}
