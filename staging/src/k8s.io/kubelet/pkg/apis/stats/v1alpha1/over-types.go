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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Summary is a top-level container for holding NodeStats and PodStats.
type Summary struct {
	Node NodeStats  `json:"node"`
	Pods []PodStats `json:"pods"`
}

// NodeStats holds node-level unprocessed sample stats.
type NodeStats struct {
	// Reference to the measured Node.
	NodeName string `json:"nodeName"`
	// Stats of system daemons tracked as raw containers.
	// The system containers are named according to the SystemContainer* constants.
	// +optional
	// +patchMergeKey=name
	// +patchStrategy=merge
	SystemContainers []ContainerStats `json:"systemContainers,omitempty" patchStrategy:"merge" patchMergeKey:"name"`
	// The time at which data collection for the node-scoped (i.e. aggregate) stats was (re)started.
	StartTime metav1.Time `json:"startTime"`
	// Stats pertaining to CPU resources.
	// +optional
	CPU *CPUStats `json:"cpu,omitempty"`
	// Stats pertaining to memory (RAM) resources.
	// +optional
	Memory *MemoryStats `json:"memory,omitempty"`
	// Stats pertaining to network resources.
	// +optional
	Network *NetworkStats `json:"network,omitempty"`
	// Stats pertaining to total usage of filesystem resources on the rootfs used by node k8s components.
	// NodeFs.Used is the total bytes used on the filesystem.
	// +optional
	Fs *FsStats `json:"fs,omitempty"`
	// Stats about the underlying container runtime.
	// +optional
	Runtime *RuntimeStats `json:"runtime,omitempty"`
	// Stats about the rlimit of system.
	// +optional
	Rlimit *RlimitStats `json:"rlimit,omitempty"`
}

// RlimitStats are stats rlimit of OS.
type RlimitStats struct {
	Time                  metav1.Time `json:"time"`              // 这些统计信息的更新时间.
	MaxPID                *int64      `json:"maxpid,omitempty"`  // 操作系统中可用的最大进程数（在Linux上是线程数）,参见getrlimit(2)中的RLIMIT_NPROC.操作系统的进程ID数量上限.
	NumOfRunningProcesses *int64      `json:"curproc,omitempty"` // 操作系统中正在运行的进程数（在Linux上是线程数）.
}

// RuntimeStats are stats pertaining to the underlying container runtime.
type RuntimeStats struct {
	// 描述底层文件系统的统计信息,该文件系统用于存储容器镜像.这个文件系统可能与主（根）文件系统相同.这里的使用情况是指文件系统上镜像占用的总字节数.
	// +optional
	ImageFs *FsStats `json:"imageFs,omitempty"`
}

const (
	SystemContainerKubelet = "kubelet" // 用于跟踪Kubelet使用情况的系统容器的名称.
	SystemContainerRuntime = "runtime" // 用于跟踪运行时（例如docker）使用情况的系统容器的名称.
	SystemContainerMisc    = "misc"    // 用于跟踪非Kubernetes进程使用情况的系统容器的名称.
	SystemContainerPods    = "pods"    // 用于跟踪用户Pod使用情况的系统容器的名称.
)

// ProcessStats are stats pertaining to processes.
type ProcessStats struct {
	// Number of processes
	// +optional
	ProcessCount *uint64 `json:"process_count,omitempty"`
}

// PodStats holds pod-level unprocessed sample stats.
type PodStats struct {
	// Reference to the measured Pod.
	PodRef PodReference `json:"podRef"`
	// The time at which data collection for the pod-scoped (e.g. network) stats was (re)started.
	StartTime metav1.Time `json:"startTime"`
	// Stats of containers in the measured pod.
	// +patchMergeKey=name
	// +patchStrategy=merge
	Containers []ContainerStats `json:"containers" patchStrategy:"merge" patchMergeKey:"name"`
	// Stats pertaining to CPU resources consumed by pod cgroup (which includes all containers' resource usage and pod overhead).
	// +optional
	CPU *CPUStats `json:"cpu,omitempty"`
	// Stats pertaining to memory (RAM) resources consumed by pod cgroup (which includes all containers' resource usage and pod overhead).
	// +optional
	Memory *MemoryStats `json:"memory,omitempty"`
	// Stats pertaining to network resources.
	// +optional
	Network *NetworkStats `json:"network,omitempty"`
	// Stats pertaining to volume usage of filesystem resources.
	// VolumeStats.UsedBytes is the number of bytes used by the Volume
	// +optional
	// +patchMergeKey=name
	// +patchStrategy=merge
	VolumeStats []VolumeStats `json:"volume,omitempty" patchStrategy:"merge" patchMergeKey:"name"`
	// EphemeralStorage reports the total filesystem usage for the containers and emptyDir-backed volumes in the measured Pod.
	// +optional
	EphemeralStorage *FsStats `json:"ephemeral-storage,omitempty"`
	// ProcessStats pertaining to processes.
	// +optional
	ProcessStats *ProcessStats `json:"process_stats,omitempty"`
}

// ContainerStats 保存容器级未处理的样本状态.
type ContainerStats struct {
	Name      string      `json:"name"`      // 容器的名称.
	StartTime metav1.Time `json:"startTime"` // 数据收集开始的时间.
	// +optional
	CPU *CPUStats `json:"cpu,omitempty"` // 关于CPU资源的统计信息,包括CPU使用率、CPU时间等等.
	// +optional
	Memory       *MemoryStats       `json:"memory,omitempty"`       // 关于内存资源的统计信息,包括内存使用量、内存限制等等.
	Accelerators []AcceleratorStats `json:"accelerators,omitempty"` // 加速器的度量指标,每个加速器对应一个AcceleratorStats结构体.
	// +optional
	Rootfs *FsStats `json:"rootfs,omitempty"` // 关于容器根文件系统使用的统计信息,包括使用的字节数、限制等等.
	// +optional
	Logs *FsStats `json:"logs,omitempty"` // 关于容器日志使用的统计信息,包括使用的字节数、限制等等.
	// 用户定义的度量指标,这些指标由容器中的应用程序暴露出来,通常只有一个容器会暴露这些指标,如果有多个容器暴露,它们将被合并在这里.
	// +patchMergeKey=name
	// +patchStrategy=merge
	UserDefinedMetrics []UserDefinedMetric `json:"userDefinedMetrics,omitempty" patchStrategy:"merge" patchMergeKey:"name"`
}

// PodReference contains enough information to locate the referenced pod.
type PodReference struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	UID       string `json:"uid"`
}

// InterfaceStats contains resource value data about interface.
type InterfaceStats struct {
	// The name of the interface
	Name string `json:"name"`
	// Cumulative count of bytes received.
	// +optional
	RxBytes *uint64 `json:"rxBytes,omitempty"`
	// Cumulative count of receive errors encountered.
	// +optional
	RxErrors *uint64 `json:"rxErrors,omitempty"`
	// Cumulative count of bytes transmitted.
	// +optional
	TxBytes *uint64 `json:"txBytes,omitempty"`
	// Cumulative count of transmit errors encountered.
	// +optional
	TxErrors *uint64 `json:"txErrors,omitempty"`
}

// NetworkStats contains data about network resources.
type NetworkStats struct {
	// The time at which these stats were updated.
	Time metav1.Time `json:"time"`

	// Stats for the default interface, if found
	InterfaceStats `json:",inline"`

	Interfaces []InterfaceStats `json:"interfaces,omitempty"`
}

// CPUStats contains data about CPU usage.
type CPUStats struct {
	// The time at which these stats were updated.
	Time metav1.Time `json:"time"`
	// Total CPU usage (sum of all cores) averaged over the sample window.
	// The "core" unit can be interpreted as CPU core-nanoseconds per second.
	// +optional
	UsageNanoCores *uint64 `json:"usageNanoCores,omitempty"`
	// Cumulative CPU usage (sum of all cores) since object creation.
	// +optional
	UsageCoreNanoSeconds *uint64 `json:"usageCoreNanoSeconds,omitempty"`
}

// MemoryStats contains data about memory usage.
type MemoryStats struct {
	// The time at which these stats were updated.
	Time metav1.Time `json:"time"`
	// Available memory for use.  This is defined as the memory limit - workingSetBytes.
	// If memory limit is undefined, the available bytes is omitted.
	// +optional
	AvailableBytes *uint64 `json:"availableBytes,omitempty"`
	// Total memory in use. This includes all memory regardless of when it was accessed.
	// +optional
	UsageBytes *uint64 `json:"usageBytes,omitempty"`
	// 工作集内存的数量.这包括最近访问的内存、脏内存和内核内存. WorkingSetBytes is <= UsageBytes[包括缓存]
	// +optional
	WorkingSetBytes *uint64 `json:"workingSetBytes,omitempty"`
	// The amount of anonymous and swap cache memory (includes transparent
	// hugepages).
	// +optional
	RSSBytes *uint64 `json:"rssBytes,omitempty"`
	// Cumulative number of minor page faults.
	// +optional
	PageFaults *uint64 `json:"pageFaults,omitempty"`
	// Cumulative number of major page faults.
	// +optional
	MajorPageFaults *uint64 `json:"majorPageFaults,omitempty"`
}

type AcceleratorStats struct {
	Make        string `json:"make"`         // 加速器的制造商,例如nvidia、amd、google等.
	Model       string `json:"model"`        // 加速器的型号,例如tesla-p100、tesla-k80等.
	ID          string `json:"id"`           // 加速器的ID.
	MemoryTotal uint64 `json:"memory_total"` // 加速器总内存大小,单位为字节.
	MemoryUsed  uint64 `json:"memory_used"`  // 加速器已分配内存大小,单位为字节.
	DutyCycle   uint64 `json:"duty_cycle"`   // 加速器在过去的采样时间内活跃处理的时间百分比.
}

// VolumeStats contains data about Volume filesystem usage.
type VolumeStats struct {
	// Embedded FsStats
	FsStats `json:",inline"`
	// Name is the name given to the Volume
	// +optional
	Name string `json:"name,omitempty"`
	// Reference to the PVC, if one exists
	// +optional
	PVCRef *PVCReference `json:"pvcRef,omitempty"`

	// VolumeHealthStats contains data about volume health
	// +optional
	VolumeHealthStats *VolumeHealthStats `json:"volumeHealthStats,omitempty"`
}

// VolumeHealthStats contains data about volume health.
type VolumeHealthStats struct {
	// Normal volumes are available for use and operating optimally.
	// An abnormal volume does not meet these criteria.
	Abnormal bool `json:"abnormal"` // 不正常的
}

// PVCReference contains enough information to describe the referenced PVC.
type PVCReference struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// FsStats contains data about filesystem usage.
type FsStats struct {
	// 这些统计信息的更新时间.
	Time metav1.Time `json:"time"`
	// 文件系统可用的存储空间（以字节为单位）.
	// +optional
	AvailableBytes *uint64 `json:"availableBytes,omitempty"`
	// 文件系统底层存储的总容量（以字节为单位）.
	// +optional
	CapacityBytes *uint64 `json:"capacityBytes,omitempty"`
	// 文件系统上特定任务使用的字节数.这可能与文件系统上使用的总字节数不同,并且可能不等于 CapacityBytes - AvailableBytes.
	// +optional
	UsedBytes *uint64 `json:"usedBytes,omitempty"`
	// 文件系统中空闲的inode数.
	// +optional
	InodesFree *uint64 `json:"inodesFree,omitempty"`
	// 文件系统中的总inode数.
	// +optional
	Inodes *uint64 `json:"inodes,omitempty"`
	// 文件系统使用的inode数.这可能不等于Inodes - InodesFree,因为这个文件系统可能与其他“文件系统”共享inode.例如,对于ContainerStats.Rootfs,这是仅由该容器使用的inode,不计算其他容器使用的inode.
	InodesUsed *uint64 `json:"inodesUsed,omitempty"`
}

// UserDefinedMetricType defines how the metric should be interpreted by the user.
type UserDefinedMetricType string

const (
	MetricGauge      UserDefinedMetricType = "gauge"      // 表示瞬时值,它可以增加或减少.
	MetricCumulative UserDefinedMetricType = "cumulative" // 表示类似于计数器的值,只会增加,不会减少.
	MetricDelta      UserDefinedMetricType = "delta"      // 表示一个时间段内的速率.
)

// UserDefinedMetricDescriptor contains metadata that describes a user defined metric.
type UserDefinedMetricDescriptor struct {
	// The name of the metric.
	Name string `json:"name"`

	// Type of the metric.
	Type UserDefinedMetricType `json:"type"`

	// Display Units for the stats.
	Units string `json:"units"`

	// Metadata labels associated with this metric.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
}

// UserDefinedMetric represents a metric defined and generated by users.
type UserDefinedMetric struct {
	UserDefinedMetricDescriptor `json:",inline"`
	// The time at which these stats were updated.
	Time metav1.Time `json:"time"`
	// Value of the metric. Float64s have 53 bit precision.
	// We do not foresee any metrics exceeding that value.
	Value float64 `json:"value"`
}
