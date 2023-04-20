// Copyright 2015 Google Inc. All Rights Reserved.
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

package v2

import (
	"time"

	// TODO(rjnagal): Remove dependency after moving all stats structs from v1.
	// using v1 now for easy conversion.
	v1 "github.com/google/cadvisor/info/v1"
)

const (
	TypeName   = "name"
	TypeDocker = "docker"
)

type CpuSpec struct {
	Limit    uint64 `json:"limit"`     // 请求的CPU共享比例。默认值为1024。
	MaxLimit uint64 `json:"max_limit"` // 请求的CPU硬限制。默认值为无限制（0）。单位为毫秒CPU。
	// TODO(rjnagal): Add a library to convert mask string to set of cpu bitmask.
	Mask   string `json:"mask,omitempty"`   // CPU亲和性掩码。
	Quota  uint64 `json:"quota,omitempty"`  // CPU配额。默认为禁用。
	Period uint64 `json:"period,omitempty"` // CPU参考时间，单位为纳秒。例如，配额与此参考时间进行比较。
}

type MemorySpec struct {
	Limit       uint64 `json:"limit,omitempty"`       // 请求的内存限制。默认值为无限制（-1）。单位为字节。
	Reservation uint64 `json:"reservation,omitempty"` // 保证的内存量。默认值为0。单位为字节。
	SwapLimit   uint64 `json:"swap_limit,omitempty"`  // 请求的交换空间限制。默认值为无限制（-1）。单位为字节。
}

type ContainerInfo struct {
	Spec  ContainerSpec     `json:"spec,omitempty"`  // 容器描述
	Stats []*ContainerStats `json:"stats,omitempty"` // 容器的历史统计信息
}

type ContainerSpec struct {
	CreationTime     time.Time         `json:"creation_time,omitempty"`  // 容器创建的时间。
	Aliases          []string          `json:"aliases,omitempty"`        // 容器在某个命名空间中的其他名称。
	Namespace        string            `json:"namespace,omitempty"`      // 容器别名的命名空间。
	Labels           map[string]string `json:"labels,omitempty"`         // 与容器关联的元数据标签。
	Envs             map[string]string `json:"envs,omitempty"`           // 与容器关联的元数据环境变量。
	HasCpu           bool              `json:"has_cpu"`                  // 是否有CPU限制。
	Cpu              CpuSpec           `json:"cpu,omitempty"`            // CPU限制的规格信息。
	HasMemory        bool              `json:"has_memory"`               // 是否有内存限制。
	Memory           MemorySpec        `json:"memory,omitempty"`         // 内存限制的规格信息。
	HasHugetlb       bool              `json:"has_hugetlb"`              // 是否使用了大页面。
	HasCustomMetrics bool              `json:"has_custom_metrics"`       // 是否有自定义度量指标。
	CustomMetrics    []v1.MetricSpec   `json:"custom_metrics,omitempty"` // 自定义度量指标的规格信息。
	HasProcesses     bool              `json:"has_processes"`            // 是否有进程限制。
	Processes        v1.ProcessSpec    `json:"processes,omitempty"`      // 进程限制的规格信息。
	HasNetwork       bool              `json:"has_network"`              // 是否有网络隔离。
	HasFilesystem    bool              `json:"has_filesystem"`           // 是否有文件系统隔离。
	HasDiskIo        bool              `json:"has_diskio"`               // 是否有磁盘I/O限制。
	Image            string            `json:"image,omitempty"`          // 用于此容器的镜像名称。
}

type ContainerStats struct {
	Timestamp        time.Time                   `json:"timestamp"`                   // 统计信息的时间戳。
	Cpu              *v1.CpuStats                `json:"cpu,omitempty"`               // 关于CPU资源的统计信息，包括CPU使用时间、CPU周期等等。
	CpuInst          *CpuInstStats               `json:"cpu_inst,omitempty"`          // 瞬时CPU使用率的统计信息，单位为纳秒/秒。
	DiskIo           *v1.DiskIoStats             `json:"diskio,omitempty"`            // 关于磁盘I/O的统计信息，包括读写速率、读写次数等等。
	Memory           *v1.MemoryStats             `json:"memory,omitempty"`            // 关于内存资源的统计信息，包括内存使用量、内存限制等等。
	Hugetlb          *map[string]v1.HugetlbStats `json:"hugetlb,omitempty"`           // 关于大页面的统计信息。
	Network          *NetworkStats               `json:"network,omitempty"`           // 关于网络流量的统计信息，包括接收和发送的数据量、数据包数量等等。
	Processes        *v1.ProcessStats            `json:"processes,omitempty"`         // 关于进程的统计信息，包括进程数量、进程状态等等。
	Filesystem       *FilesystemStats            `json:"filesystem,omitempty"`        // 关于文件系统的统计信息，包括使用的字节数、限制等等。
	Load             *v1.LoadStats               `json:"load_stats,omitempty"`        // 关于任务负载的统计信息。
	Accelerators     []v1.AcceleratorStats       `json:"accelerators,omitempty"`      // 加速器的度量指标，每个加速器对应一个AcceleratorStats结构体。
	CustomMetrics    map[string][]v1.MetricVal   `json:"custom_metrics,omitempty"`    // 自定义度量指标的统计信息，以键值对的形式存储。
	PerfStats        []v1.PerfStat               `json:"perf_stats,omitempty"`        // 性能事件计数器的统计信息。
	PerfUncoreStats  []v1.PerfUncoreStat         `json:"perf_uncore_stats,omitempty"` // 来自性能非核心事件的统计信息。仅适用于根容器。
	ReferencedMemory uint64                      `json:"referenced_memory,omitempty"` // 引用内存的统计信息。
	Resctrl          v1.ResctrlStats             `json:"resctrl,omitempty"`           // 资源控制（resctrl）的统计信息。
}

type Percentiles struct {
	// Indicates whether the stats are present or not.
	// If true, values below do not have any data.
	Present bool `json:"present"`
	// Average over the collected sample.
	Mean uint64 `json:"mean"`
	// Max seen over the collected sample.
	Max uint64 `json:"max"`
	// 50th percentile over the collected sample.
	Fifty uint64 `json:"fifty"`
	// 90th percentile over the collected sample.
	Ninety uint64 `json:"ninety"`
	// 95th percentile over the collected sample.
	NinetyFive uint64 `json:"ninetyfive"`
}

type Usage struct {
	// Indicates amount of data available [0-100].
	// If we have data for half a day, we'll still process DayUsage,
	// but set PercentComplete to 50.
	PercentComplete int32 `json:"percent_complete"`
	// Mean, Max, and 90p cpu rate value in milliCpus/seconds. Converted to milliCpus to avoid floats.
	Cpu Percentiles `json:"cpu"`
	// Mean, Max, and 90p memory size in bytes.
	Memory Percentiles `json:"memory"`
}

// latest sample collected for a container.
type InstantUsage struct {
	// cpu rate in cpu milliseconds/second.
	Cpu uint64 `json:"cpu"`
	// Memory usage in bytes.
	Memory uint64 `json:"memory"`
}

type DerivedStats struct {
	// Time of generation of these stats.
	Timestamp time.Time `json:"timestamp"`
	// Latest instantaneous sample.
	LatestUsage InstantUsage `json:"latest_usage"`
	// Percentiles in last observed minute.
	MinuteUsage Usage `json:"minute_usage"`
	// Percentile in last hour.
	HourUsage Usage `json:"hour_usage"`
	// Percentile in last day.
	DayUsage Usage `json:"day_usage"`
}

type FsInfo struct {
	// Time of generation of these stats.
	Timestamp time.Time `json:"timestamp"`

	// The block device name associated with the filesystem.
	Device string `json:"device"`

	// Path where the filesystem is mounted.
	Mountpoint string `json:"mountpoint"`

	// Filesystem usage in bytes.
	Capacity uint64 `json:"capacity"`

	// Bytes available for non-root use.
	Available uint64 `json:"available"`

	// Number of bytes used on this filesystem.
	Usage uint64 `json:"usage"`

	// Labels associated with this filesystem.
	Labels []string `json:"labels"`

	// Number of Inodes.
	Inodes *uint64 `json:"inodes,omitempty"`

	// Number of available Inodes (if known)
	InodesFree *uint64 `json:"inodes_free,omitempty"`
}

type RequestOptions struct {
	// Type of container identifier specified - TypeName (default) or TypeDocker
	IdType string `json:"type"`
	// Number of stats to return, -1 means no limit.
	Count     int            `json:"count"`
	Recursive bool           `json:"recursive"` // 是否包含子容器的统计信息
	MaxAge    *time.Duration `json:"max_age"`   // 更新大于MaxAge的统计信息 nil表示不更新，0总是触发更新。
}

type ProcessInfo struct {
	User          string  `json:"user"`
	Pid           int     `json:"pid"`
	Ppid          int     `json:"parent_pid"`
	StartTime     string  `json:"start_time"`
	PercentCpu    float32 `json:"percent_cpu"`
	PercentMemory float32 `json:"percent_mem"`
	RSS           uint64  `json:"rss"`
	VirtualSize   uint64  `json:"virtual_size"`
	Status        string  `json:"status"`
	RunningTime   string  `json:"running_time"`
	CgroupPath    string  `json:"cgroup_path"`
	Cmd           string  `json:"cmd"`
	FdCount       int     `json:"fd_count"`
	Psr           int     `json:"psr"`
}

type TcpStat struct {
	Established uint64
	SynSent     uint64
	SynRecv     uint64
	FinWait1    uint64
	FinWait2    uint64
	TimeWait    uint64
	Close       uint64
	CloseWait   uint64
	LastAck     uint64
	Listen      uint64
	Closing     uint64
}

type NetworkStats struct {
	Interfaces  []v1.InterfaceStats `json:"interfaces,omitempty"` // 按接口分组的网络统计信息，每个接口对应一个InterfaceStats结构体。
	Tcp         TcpStat             `json:"tcp"`                  // TCP连接的统计信息，包括已建立、监听等等。
	Tcp6        TcpStat             `json:"tcp6"`                 // IPv6 TCP连接的统计信息，包括已建立、监听等等。
	Udp         v1.UdpStat          `json:"udp"`                  // UDP连接的统计信息。
	Udp6        v1.UdpStat          `json:"udp6"`                 // IPv6 UDP连接的统计信息。
	TcpAdvanced v1.TcpAdvancedStat  `json:"tcp_advanced"`         // TCP高级统计信息。
}

// Instantaneous CPU stats
type CpuInstStats struct {
	Usage CpuInstUsage `json:"usage"`
}

// CPU usage time statistics.
type CpuInstUsage struct {
	// Total CPU usage.
	// Units: nanocores per second
	Total uint64 `json:"total"`

	// Per CPU/core usage of the container.
	// Unit: nanocores per second
	PerCpu []uint64 `json:"per_cpu_usage,omitempty"`

	// Time spent in user space.
	// Unit: nanocores per second
	User uint64 `json:"user"`

	// Time spent in kernel space.
	// Unit: nanocores per second
	System uint64 `json:"system"`
}

// FilesystemStats 文件系统的统计信息
type FilesystemStats struct {
	TotalUsageBytes *uint64 `json:"totalUsageBytes,omitempty"`        // 容器使用的总字节数
	BaseUsageBytes  *uint64 `json:"baseUsageBytes,omitempty"`         // 容器通过其根文件系统使用的字节数
	InodeUsage      *uint64 `json:"containter_inode_usage,omitempty"` // 容器根文件系统中使用的inode数
}
