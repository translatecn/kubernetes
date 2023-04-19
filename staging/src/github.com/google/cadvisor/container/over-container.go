// Copyright 2014 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package container defines types for sub-container events and also
// defines an interface for container operation handlers.
package container

import info "github.com/google/cadvisor/info/v1"

// ListType describes whether listing should be just for a
// specific container or performed recursively.
type ListType int

const (
	ListSelf      ListType = iota
	ListRecursive          //列表递归
)

type ContainerType int

const (
	ContainerTypeRaw ContainerType = iota
	ContainerTypeDocker
	ContainerTypeCrio
	ContainerTypeContainerd
	ContainerTypeMesos
)

// ContainerHandler 用于处理容器信息的接口，它定义了一组用于获取和处理容器信息的方法。
// 容器操作处理器是一个用于处理容器操作的组件，例如启动、停止、重启、删除容器等。
// 通过定义一个容器操作处理器接口，可以使得不同的容器操作处理器实现可以互相替换，并且可以方便地进行扩展和定制。
type ContainerHandler interface {
	ContainerReference() (info.ContainerReference, error)                // 返回容器引用（ContainerReference）。是一个包含容器ID和名称的结构体，用于唯一标识容器。
	GetSpec() (info.ContainerSpec, error)                                // 返回容器的隔离规范（isolation spec）。隔离规范可以用于描述容器的隔离级别、资源限制、网络配置等等。隔离规范通常是由容器运行时（如Docker）提供，并在容器创建时传递给cAdvisor。
	GetStats() (*info.ContainerStats, error)                             // 返回容器的当前统计信息。
	ListContainers(listType ListType) ([]info.ContainerReference, error) // 返回此pod容器的子容器。
	ListProcesses(listType ListType) ([]int, error)                      // 返回此容器内的进程。
	GetCgroupPath(resource string) (string, error)                       // 返回请求资源的绝对 cgroup 路径。
	GetContainerLabels() map[string]string                               // 获取容器的标签信息
	GetContainerIPAddress() string                                       // 获取容器的IP地址
	Exists() bool                                                        // 检查容器是否存在
	Cleanup()
	Start()
	Type() ContainerType
}
