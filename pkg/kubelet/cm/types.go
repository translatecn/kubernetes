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

package cm

import (
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

// ResourceConfig 包含了所有支持的 cgroup 资源参数的信息.
type ResourceConfig struct {
	Memory        *int64            // 内存限制（以字节为单位）.
	CpuShares     *uint64           // CPU 分配权重（与其他容器相对比）.
	CpuQuota      *int64            // CPU 硬性限制（以微秒为单位）.
	CpuPeriod     *uint64           // CPU 限制周期（以微秒为单位）.
	HugePageLimit map[int64]int64   // 从页面大小（以字节为单位）到限制（以字节为单位）的映射.
	PidsLimit     *int64            // 最大进程数限制.
	Unified       map[string]string // 用于 cgroup v2.
}

// CgroupName is the abstract name of a cgroup prior to any driver specific conversion.
// It is specified as a list of strings from its individual components, such as:
// {"kubepods", "burstable", "pod1234-abcd-5678-efgh"}
type CgroupName []string //  cgroup 层级

// CgroupConfig 这是一个通用的对象,用于向 systemd 和原始 cgroup fs 实现的 Cgroup Manager 接口指定 cgroup 信息.
type CgroupConfig struct {
	Name               CgroupName
	ResourceParameters *ResourceConfig // cgroup 设置
}

// CgroupManager allows for cgroup management.
// Supports Cgroup Creation ,Deletion and Updates.
type CgroupManager interface {
	// Create creates and applies the cgroup configurations on the cgroup.
	// It just creates the leaf cgroups.
	// It expects the parent cgroup to already exist.
	Create(*CgroupConfig) error
	// Destroy the cgroup.
	Destroy(*CgroupConfig) error
	Update(*CgroupConfig) error
	// Validate checks if the cgroup is valid
	Validate(name CgroupName) error
	// Exists checks if the cgroup already exists
	Exists(name CgroupName) bool
	Name(name CgroupName) string // 不同的 cgroup 驱动程序可能会对 cgroup 的名称进行不同的转换  {"kubepods", "besteffort"} -> /kubepods.slice/kubepods-besteffort.slice
	// CgroupName converts the literal cgroupfs name on the host to an internal identifier.
	CgroupName(name string) CgroupName
	Pids(name CgroupName) []int                  // 扫描所有子系统以查找与指定 cgroup 相关联的 pid.
	ReduceCPULimits(cgroupName CgroupName) error // 将CPU CFS值减少到最小的共享数量.用于限制进程使用CPU的时间
	MemoryUsage(name CgroupName) (int64, error)  // 从 cgroupfs 读取指定 cgroup 的当前内存使用情况,并返回该值. memory.usage_in_bytes
}

// QOSContainersInfo stores the names of containers per qos
type QOSContainersInfo struct {
	Guaranteed CgroupName
	BestEffort CgroupName
	Burstable  CgroupName
}

// PodContainerManager 存储和管理pod 级别的容器,与pod worker 交互
type PodContainerManager interface {
	GetPodContainerName(*v1.Pod) (CgroupName, string)
	EnsureExists(*v1.Pod) error                               // 在 qos 启用下,确认pod cgroup 存在,不存在 创建
	Exists(*v1.Pod) bool                                      // 判断一个pod 的cgroup 路径是否存在
	Destroy(name CgroupName) error                            // 通过cgroup删除容器
	ReduceCPULimits(name CgroupName) error                    // 将CPU CFS值减少到最小的共享数量.用于限制进程使用CPU的时间
	GetAllPodsFromCgroups() (map[types.UID]CgroupName, error) // 根据cgroupfs系统的状态,返回一组pod id到它们相关联的cgroup.
	IsPodCgroup(cgroupfs string) (bool, types.UID)            // 返回 cgroupfs 名称对应于一个 Pod
}
