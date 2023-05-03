package configs

import (
	systemdDbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/opencontainers/runc/libcontainer/devices"
)

type FreezerState string

const (
	Undefined FreezerState = ""
	Frozen    FreezerState = "FROZEN"
	Thawed    FreezerState = "THAWED"
)

// Cgroup holds properties of a cgroup on Linux.
type Cgroup struct {
	Name         string                 `json:"name,omitempty"`   // Name 指定了 cgroup 的名称.
	Parent       string                 `json:"parent,omitempty"` // Parent 指定了 cgroup 或者 slice 的父级名称.
	Path         string                 `json:"path"`             // Path 指定了容器创建和/或加入的 cgroup 的路径.路径相对于主机系统的 cgroup 挂载点.
	ScopePrefix  string                 `json:"scope_prefix"`     // ScopePrefix 描述了范围名称的前缀.
	*Resources                          // Resources 包含要应用的各种 cgroup 设置.
	Systemd      bool                   // Systemd 指示是否使用 systemd 来管理 cgroups.
	SystemdProps []systemdDbus.Property `json:"-"` // SystemdProps 是从 org.systemd.property.xxx 注释中派生的 systemd 的任何其他属性. 除非使用 systemd 管理 cgroups,否则将被忽略.
	Rootless     bool                   // 指示是否使用 rootless cgroups.
	// OwnerUID 指定应拥有 cgroup 的主机 UID,如果为 nil,则接受默认所有权.
	// 只有在 cgroupfs 要挂载为读/写时才应设置此项.
	// 并非所有 cgroup 管理器实现都支持更改所有权.
	OwnerUID *int `json:"owner_uid,omitempty"`
}

type Resources struct {
	Devices                      []*devices.Rule      `json:"devices"`                          // 容器中设备的访问规则集合.
	Memory                       int64                `json:"memory"`                           // 内存限制 bytes
	MemoryReservation            int64                `json:"memory_reservation"`               // 内存预留或软限制（以字节为单位）
	MemorySwap                   int64                `json:"memory_swap"`                      // 总内存使用量（内存+交换空间）;将其设置为 -1 以启用无限制的交换空间.
	CpuShares                    uint64               `json:"cpu_shares"`                       // CPU 分配比例（与其他容器相对权重）
	CpuQuota                     int64                `json:"cpu_quota"`                        // CPU 硬限制上限（以微秒为单位）.给定时间段内允许的 CPU 时间.
	CpuPeriod                    uint64               `json:"cpu_period"`                       // 用于硬限制的 CPU 周期（以微秒为单位）.为 0 时使用系统默认值.
	CpuRtRuntime                 int64                `json:"cpu_rt_quota"`                     // 实时调度中 CPU 使用的时间（以微秒为单位）.
	CpuRtPeriod                  uint64               `json:"cpu_rt_period"`                    // 用于实时调度的 CPU 周期（以微秒为单位）.
	CpusetCpus                   string               `json:"cpuset_cpus"`                      // 使用的CPU
	CpusetMems                   string               `json:"cpuset_mems"`                      // 使用的MEM
	PidsLimit                    int64                `json:"pids_limit"`                       // 进程限制;将其设置为 <= 0 以禁用限制.
	BlkioWeight                  uint16               `json:"blkio_weight"`                     // 指定每个 cgroup 的权重,范围从 10 到 1000.
	BlkioLeafWeight              uint16               `json:"blkio_leaf_weight"`                // 指定给定 cgroup 中任务的权重,与 cgroup 的子 cgroup 竞争,范围从 10 到 1000,仅适用于 cfq 调度器.
	BlkioWeightDevice            []*WeightDevice      `json:"blkio_weight_device"`              // 每个设备每个 cgroup 的权重,可以覆盖 BlkioWeight.
	BlkioThrottleReadBpsDevice   []*ThrottleDevice    `json:"blkio_throttle_read_bps_device"`   // 每个设备每个 cgroup 的 IO 读入速率限制,以每秒读入bytes数.
	BlkioThrottleWriteBpsDevice  []*ThrottleDevice    `json:"blkio_throttle_write_bps_device"`  // 每个设备每个 cgroup 的 IO 写入速率限制,以每秒写入bytes数.
	BlkioThrottleReadIOPSDevice  []*ThrottleDevice    `json:"blkio_throttle_read_iops_device"`  // 每个设备每个 cgroup 的 IO 读入速率限制,以每秒 IO 次数计.
	BlkioThrottleWriteIOPSDevice []*ThrottleDevice    `json:"blkio_throttle_write_iops_device"` // 每个设备每个 cgroup 的 IO 写入速率限制,以每秒 IO 次数计.
	Freezer                      FreezerState         `json:"freezer"`                          // 设置进程的冻结值.
	HugetlbLimit                 []*HugepageLimit     `json:"hugetlb_limit"`                    // 大页限制
	OomKillDisable               bool                 `json:"oom_kill_disable"`                 // 是否禁用oom killer
	MemorySwappiness             *uint64              `json:"memory_swappiness"`                // 调整每个 cgroup 的交换行为.
	NetPrioIfpriomap             []*IfPrioMap         `json:"net_prio_ifpriomap"`               // 设置容器的网络流量优先级.
	NetClsClassid                uint32               `json:"net_cls_classid_u"`                // 为容器的网络数据包设置类别标识符.
	Rdma                         map[string]LinuxRdma `json:"rdma"`                             // 资源限制配置.
	CpuWeight                    uint64               `json:"cpu_weight"`                       // 设置比例带宽限制.
	Unified                      map[string]string    `json:"unified"`                          // 仅适用于 cgroupv2 的键值对映射.
	SkipDevices                  bool                 `json:"-"`                                // SkipDevices允许跳过配置设备权限。例如，kubelet在创建父cgroup (kubepods)时使用，这在许多容器中都很常见，并且在运行update时使用。
	// SkipFreezeOnSet是cgroup管理器在设置资源时跳过cgroup冻结的标志。仅适用于systemd遗留(即cgroup v1)管理器(默认情况下使用freeze来避免由于systemd无法以非中断方式更新设备规则而导致的虚假权限错误)。
	// 如果没有设置，可以使用一些方法(例如查看cgroup的设备)。在Set()期间使用list和查询systemd单元属性来确定是否需要冻结。这些//方法可能相对较慢，因此使用此标志。
	SkipFreezeOnSet bool `json:"-"`
}
