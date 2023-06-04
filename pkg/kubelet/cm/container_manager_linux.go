//go:build linux
// +build linux

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

package cm

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/manager"
	"github.com/opencontainers/runc/libcontainer/configs"
	"k8s.io/klog/v2"
	"k8s.io/mount-utils"
	utilpath "k8s.io/utils/path"

	libcontaineruserns "github.com/opencontainers/runc/libcontainer/userns"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
	utilsysctl "k8s.io/component-helpers/node/util/sysctl"
	internalapi "k8s.io/cri-api/pkg/apis"
	podresourcesapi "k8s.io/kubelet/pkg/apis/podresources/v1"
	kubefeatures "k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/pkg/kubelet/cadvisor"
	"k8s.io/kubernetes/pkg/kubelet/cm/containermap"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpumanager"
	"k8s.io/kubernetes/pkg/kubelet/cm/devicemanager"
	"k8s.io/kubernetes/pkg/kubelet/cm/dra"
	"k8s.io/kubernetes/pkg/kubelet/cm/memorymanager"
	memorymanagerstate "k8s.io/kubernetes/pkg/kubelet/cm/memorymanager/state"
	"k8s.io/kubernetes/pkg/kubelet/cm/topologymanager"
	cmutil "k8s.io/kubernetes/pkg/kubelet/cm/util"
	"k8s.io/kubernetes/pkg/kubelet/config"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/lifecycle"
	"k8s.io/kubernetes/pkg/kubelet/pluginmanager/cache"
	"k8s.io/kubernetes/pkg/kubelet/stats/pidlimit"
	"k8s.io/kubernetes/pkg/kubelet/status"
	schedulerframework "k8s.io/kubernetes/pkg/scheduler/framework"
	"k8s.io/kubernetes/pkg/util/oom"
)

// 由 Kubelet 追踪的系统级容器
type systemContainer struct {
	name            string                        // 容器的绝对名称.
	cpuMillicores   int64                         // 容器的 CPU 限制,以毫核为单位.
	ensureStateFunc func(m cgroups.Manager) error // 确保容器状态的函数.m 是指定容器的 cgroup 管理器.
	manager         cgroups.Manager               // 外部容器的 cgroups 管理器.
}

func newSystemCgroups(containerName string) (*systemContainer, error) {
	manager, err := createManager(containerName)
	if err != nil {
		return nil, err
	}
	return &systemContainer{
		name:    containerName,
		manager: manager,
	}, nil
}

type ContainerManagerImpl struct {
	sync.RWMutex                                //
	cadvisorInterface   cadvisor.Interface      // 与 cAdvisor 进行交互的接口.
	mountUtil           mount.Interface         // 与挂载系统进行交互的接口.
	NodeConfig                                  // 节点的配置信息.
	status              Status                  // 容器管理器的状态信息.
	systemContainers    []*systemContainer      // 正在被管理的外部容器.
	periodicTasks       []func()                // 定期执行的任务列表.
	subsystems          *CgroupSubsystems       // 所有已挂载的 cgroup 子系统.
	nodeInfo            *v1.Node                //
	cgroupManager       CgroupManager           // 与 cgroup 进行管理的接口.
	capacity            v1.ResourceMap          // 节点的容量信息,包括内部资源.
	internalCapacity    v1.ResourceMap          // 节点的容量信息,包括内部资源.
	cgroupRoot          CgroupName              // 绝对 cgroupfs 路径,Kubelet 需要将所有 pod 放在该路径下的顶级容器中,以实现节点可分配性.
	recorder            record.EventRecorder    // 事件记录器接口.
	qosContainerManager QOSContainerManager     // QoS cgroup 管理的接口.
	DeviceManager       devicemanager.Manager   // 设备插件 报告的设备的 导出和分配的接口.
	cpuManager          cpumanager.Manager      // cpu管理器
	memoryManager       memorymanager.Manager   // 内存管理器
	TopologyManager     topologymanager.Manager // numa 拓扑管理器 ✅
	draManager          dra.Manager             // 动态资源分配管理的接口.
}

// TopologyManager
// https://developer.aliyun.com/article/784148
// https://blog.csdn.net/qjm1993/article/details/103237944/
// https://zhuanlan.zhihu.com/p/362030360
// https://www.modb.pro/db/78825
// https://blog.csdn.net/bandaoyu/article/details/122959097
// https://zhuanlan.zhihu.com/p/554043638

type features struct {
	cpuHardcapping bool // 对 CPU 使用时间的硬限制.
}

var _ ContainerManager = &ContainerManagerImpl{}

// cgroups 是 Linux 内核的一个功能,它允许将进程组织成一组,以便对它们进行资源限制和控制.
// 在 Kubernetes 中,cgroups 用于限制容器的资源使用,例如 CPU、内存、磁盘等.
// 该函数似乎是在检查 cgroups 是否已正确配置,以确保容器能够正常运行并受到正确的资源限制.
func validateSystemRequirements(mountUtil mount.Interface) (features, error) {
	const (
		cgroupMountType = "cgroup"
		localErr        = "system validation failed"
	)
	var (
		cpuMountPoint string
		f             features
	)
	var _ = new(mount.Mounter).List

	mountPoints, err := mountUtil.List()
	if err != nil {
		return f, fmt.Errorf("%s - %v", localErr, err)
	}

	if cgroups.IsCgroup2UnifiedMode() { // cgroup v2 统一模式
		f.cpuHardcapping = true
		return f, nil
	}

	expectedCgroups := sets.NewString("cpu", "cpuacct", "cpuset", "memory")
	for _, mountPoint := range mountPoints {
		if mountPoint.Type == cgroupMountType {
			for _, opt := range mountPoint.Opts {
				if expectedCgroups.Has(opt) {
					expectedCgroups.Delete(opt)
				}
				if opt == "cpu" {
					cpuMountPoint = mountPoint.Path
				}
			}
		}
	}

	if expectedCgroups.Len() > 0 {
		return f, fmt.Errorf("%s - 以下的 Cgroup 子系统没有挂载: %v", localErr, expectedCgroups.List())
	}

	// 检查是否有可用的 CPU 配额.CPU cgroup 是必需的,因此预期此时已经挂载.
	periodExists, err := utilpath.Exists(utilpath.CheckFollowSymlink, path.Join(cpuMountPoint, "cpu.cfs_period_us")) // 是用于硬限制的 CPU 周期,以微秒为单位.
	if err != nil {
		klog.ErrorS(err, "无法检测到 CPU cgroup cpu.cfs_period_us 是否可用.")
	}
	quotaExists, err := utilpath.Exists(utilpath.CheckFollowSymlink, path.Join(cpuMountPoint, "cpu.cfs_quota_us")) // CPU 使用时间的硬限制上限,以微秒为单位.
	if err != nil {
		klog.ErrorS(err, "无法检测到 CPU cgroup cpu.cfs_quota_us 是否可用.")
	}
	if quotaExists && periodExists {
		f.cpuHardcapping = true
	}
	return f, nil
}

// NewContainerManager TODO(vmarmol): 为系统容器添加限制
// 获取指定容器的绝对名称.
// 空容器名禁用使用指定的容器.
func NewContainerManager(
	mountUtil mount.Interface,
	cadvisorInterface cadvisor.Interface,
	nodeConfig NodeConfig,
	failSwapOn bool, // 告诉Kubelet,如果在节点上启用了swap,则启动失败.
	recorder record.EventRecorder,
	kubeClient clientset.Interface,
) (ContainerManager, error) {
	subsystems, err := GetCgroupSubsystems() // 子系统
	if err != nil {
		return nil, fmt.Errorf("failed to get mounted cgroup subsystems: %v", err)
	}

	if failSwapOn { // swap开启时,kubelet不能运行,检查一下
		// 检查swap是否开启.Kubelet不支持在启用swap的情况下运行.
		swapFile := "/proc/swaps"
		swapData, err := os.ReadFile(swapFile)
		if err != nil {
			if os.IsNotExist(err) {
				klog.InfoS("File does not exist, assuming that swap is disabled", "path", swapFile)
			} else {
				return nil, err
			}
		} else {
			swapData = bytes.TrimSpace(swapData) // extra trailing \n
			swapLines := strings.Split(string(swapData), "\n")

			// If there is more than one line (table headers) in /proc/swaps, swap is enabled and we should
			// error out unless --fail-swap-on is set to false.
			if len(swapLines) > 1 {
				return nil, fmt.Errorf("running with swap on is not supported, please disable swap! or set --fail-swap-on flag to false. /proc/swaps contained: %v", swapLines)
			}
		}
	}

	// 通过cadvisorInterface提供的获取节点信息的方法获取machineInfo,从中获取资源的容量信息,遍历后取值
	var internalCapacity = v1.ResourceMap{}
	// It is safe to invoke `MachineInfo` on cAdvisor before logically initializing cAdvisor here because
	// machine info is computed and cached once as part of cAdvisor object creation.
	// But `RootFsInfo` and `ImagesFsInfo` are not available at this moment so they will be called later during manager starts
	machineInfo, err := cadvisorInterface.MachineInfo()
	if err != nil {
		return nil, err
	}
	capacity := cadvisor.CapacityFromMachineInfo(machineInfo)
	for k, v := range capacity {
		internalCapacity[k] = v
	}
	pidlimits, err := pidlimit.Stats()
	if err == nil && pidlimits != nil && pidlimits.MaxPID != nil {
		internalCapacity[pidlimit.PIDs] = *resource.NewQuantity(
			int64(*pidlimits.MaxPID),
			resource.DecimalSI)
	}

	// Turn CgroupRoot from a string (in cgroupfs path format) to internal CgroupName
	cgroupRoot := ParseCgroupfsToCgroupName(nodeConfig.CgroupRoot)
	cgroupManager := NewCgroupManager(subsystems, nodeConfig.CgroupDriver)
	// Check if Cgroup-root actually exists on the node
	if nodeConfig.CgroupsPerQOS {
		// this does default to / when enabled, but this tests against regressions.
		if nodeConfig.CgroupRoot == "" {
			return nil, fmt.Errorf("invalid configuration: cgroups-per-qos was specified and cgroup-root was not specified. To enable the QoS cgroup hierarchy you need to specify a valid cgroup-root")
		}

		// we need to check that the cgroup root actually exists for each subsystem
		// of note, we always use the cgroupfs driver when performing this check since
		// the input is provided in that format.
		// this is important because we do not want any name conversion to occur.
		if err := cgroupManager.Validate(cgroupRoot); err != nil {
			return nil, fmt.Errorf("invalid configuration: %w", err)
		}
		klog.InfoS("Container manager verified user specified cgroup-root exists", "cgroupRoot", cgroupRoot)
		// Include the top level cgroup for enforcing node allocatable into cgroup-root.
		// This way, all sub modules can avoid having to understand the concept of node allocatable.
		cgroupRoot = NewCgroupName(cgroupRoot, defaultNodeAllocatableCgroupName)
	}
	klog.InfoS("Creating Container Manager object based on Node Config", "nodeConfig", nodeConfig)

	qosContainerManager, err := NewQOSContainerManager(subsystems, cgroupRoot, nodeConfig, cgroupManager)
	if err != nil {
		return nil, err
	}

	cm := &ContainerManagerImpl{
		cadvisorInterface:   cadvisorInterface,
		mountUtil:           mountUtil,
		NodeConfig:          nodeConfig,
		subsystems:          subsystems,
		cgroupManager:       cgroupManager,
		capacity:            capacity,
		internalCapacity:    internalCapacity,
		cgroupRoot:          cgroupRoot,
		recorder:            recorder,
		qosContainerManager: qosContainerManager,
	}

	if utilfeature.DefaultFeatureGate.Enabled(kubefeatures.TopologyManager) {
		cm.TopologyManager, err = topologymanager.NewManager(
			machineInfo.Topology,                                // 机器拓扑信息
			nodeConfig.ExperimentalTopologyManagerPolicy,        // 实验性拓扑管理器策略
			nodeConfig.ExperimentalTopologyManagerScope,         // 实验性拓扑管理器范围
			nodeConfig.ExperimentalTopologyManagerPolicyOptions, // 实验性拓扑管理器策略配置
		)

		if err != nil {
			return nil, err
		}

	} else {
		cm.TopologyManager = topologymanager.NewFakeManager()
	}

	klog.InfoS("Creating device plugin manager")
	cm.DeviceManager, err = devicemanager.NewManagerImpl(machineInfo.Topology, cm.TopologyManager)
	if err != nil {
		return nil, err
	}
	cm.TopologyManager.AddHintProvider(cm.DeviceManager)

	// initialize DRA manager
	if utilfeature.DefaultFeatureGate.Enabled(kubefeatures.DynamicResourceAllocation) {
		klog.InfoS("Creating Dynamic Resource Allocation (DRA) manager")
		cm.draManager, err = dra.NewManagerImpl(kubeClient)
		if err != nil {
			return nil, err
		}
	}

	// Initialize CPU manager
	cm.cpuManager, err = cpumanager.NewManager(
		nodeConfig.CPUManagerPolicy,
		nodeConfig.CPUManagerPolicyOptions,
		nodeConfig.CPUManagerReconcilePeriod,
		machineInfo,
		nodeConfig.NodeAllocatableConfig.ReservedSystemCPUs,
		cm.GetNodeAllocatableReservation(), // 资源预留
		nodeConfig.KubeletRootDir,
		cm.TopologyManager,
	)
	if err != nil {
		klog.ErrorS(err, "Failed to initialize cpu manager")
		return nil, err
	}
	cm.TopologyManager.AddHintProvider(cm.cpuManager)

	if utilfeature.DefaultFeatureGate.Enabled(kubefeatures.MemoryManager) {
		cm.memoryManager, err = memorymanager.NewManager(
			nodeConfig.ExperimentalMemoryManagerPolicy,
			machineInfo,
			cm.GetNodeAllocatableReservation(),
			nodeConfig.ExperimentalMemoryManagerReservedMemory,
			nodeConfig.KubeletRootDir,
			cm.TopologyManager,
		)
		if err != nil {
			klog.ErrorS(err, "Failed to initialize memory manager")
			return nil, err
		}
		cm.TopologyManager.AddHintProvider(cm.memoryManager)
	}

	return cm, nil
}

func (cm *ContainerManagerImpl) NewPodContainerManager() PodContainerManager {
	if cm.NodeConfig.CgroupsPerQOS {
		return &podContainerManagerImpl{
			qosContainersInfo: cm.GetQOSContainersInfo(),
			subsystems:        cm.subsystems,
			cgroupManager:     cm.cgroupManager,
			podPidsLimit:      cm.ExperimentalPodPidsLimit,
			enforceCPULimits:  cm.EnforceCPULimits,
			// cpuCFSQuotaPeriod is in microseconds. NodeConfig.CPUCFSQuotaPeriod is time.Duration (measured in nano seconds).
			// Convert (cm.CPUCFSQuotaPeriod) [nanoseconds] / time.Microsecond (1000) to get cpuCFSQuotaPeriod in microseconds.
			cpuCFSQuotaPeriod: uint64(cm.CPUCFSQuotaPeriod / time.Microsecond),
		}
	}
	return &podContainerManagerNoop{
		cgroupRoot: cm.cgroupRoot,
	}
}

func (cm *ContainerManagerImpl) InternalContainerLifecycle() InternalContainerLifecycle {
	return &internalContainerLifecycleImpl{cm.cpuManager, cm.memoryManager, cm.TopologyManager}
}

// 创建一个 cgroup 容器管理器.
func createManager(containerName string) (cgroups.Manager, error) {
	cg := &configs.Cgroup{
		Parent: "/",
		Name:   containerName,
		Resources: &configs.Resources{
			SkipDevices: true,
		},
		Systemd: false,
	}

	return manager.New(cg)
}

type KernelTunableBehavior string

const (
	KernelTunableWarn   KernelTunableBehavior = "warn"   // 在控制台上发出警告,但不会修改内核可调整flag或返回错误.
	KernelTunableError  KernelTunableBehavior = "error"  // 发生错误时返回错误
	KernelTunableModify KernelTunableBehavior = "modify" // 修改内核可调整标志
)

// setupKernelTunables 验证内核可调整flags是否按预期设置,具体取决于指定的选项,它将警告、出错或修改内核可调整标志.
func setupKernelTunables(option KernelTunableBehavior) error {
	desiredState := map[string]int{
		utilsysctl.VMOvercommitMemory: utilsysctl.VMOvercommitMemoryAlways,
		utilsysctl.VMPanicOnOOM:       utilsysctl.VMPanicOnOOMInvokeOOMKiller,
		utilsysctl.KernelPanic:        utilsysctl.KernelPanicRebootTimeout,
		utilsysctl.KernelPanicOnOops:  utilsysctl.KernelPanicOnOopsAlways,
		utilsysctl.RootMaxKeys:        utilsysctl.RootMaxKeysSetting,
		utilsysctl.RootMaxBytes:       utilsysctl.RootMaxBytesSetting,
	}

	sysctl := utilsysctl.New()

	errList := []error{}
	for flag, expectedValue := range desiredState {
		val, err := sysctl.GetSysctl(flag)
		if err != nil {
			errList = append(errList, err)
			continue
		}
		if val == expectedValue {
			continue
		}

		switch option {
		case KernelTunableError:
			errList = append(errList, fmt.Errorf("invalid kernel flag: %v, expected value: %v, actual value: %v", flag, expectedValue, val))
		case KernelTunableWarn:
			klog.V(2).InfoS("Invalid kernel flag", "flag", flag, "expectedValue", expectedValue, "actualValue", val)
		case KernelTunableModify:
			klog.V(2).InfoS("Updating kernel flag", "flag", flag, "expectedValue", expectedValue, "actualValue", val)
			err = sysctl.SetSysctl(flag, expectedValue)
			if err != nil {
				if libcontaineruserns.RunningInUserNS() { // 0,0,4294967295
					if utilfeature.DefaultFeatureGate.Enabled(kubefeatures.KubeletInUserNamespace) {
						klog.V(2).InfoS("更新内核标志失败（正在运行于用户命名空间中,忽略）.", "flag", flag, "err", err)
						continue
					}
					klog.ErrorS(err, "更新内核标志失败（提示：启用 KubeletInUserNamespace 功能标志以忽略此错误）.", "flag", flag)
				}
				errList = append(errList, err)
			}
		}
	}
	return utilerrors.NewAggregate(errList)
}

func (cm *ContainerManagerImpl) setupNode(activePods ActivePodsFunc) error {
	f, err := validateSystemRequirements(cm.mountUtil) // 是否启用了cpu 硬限制
	if err != nil {
		return err
	}
	if !f.cpuHardcapping {
		cm.status.SoftRequirements = fmt.Errorf("CPU hardcapping unsupported")
	}
	b := KernelTunableModify
	if cm.GetNodeConfig().ProtectKernelDefaults {
		b = KernelTunableError
	}
	if err := setupKernelTunables(b); err != nil {
		return err
	}

	// Setup top level qos containers only if CgroupsPerQOS flag is specified as true
	if cm.NodeConfig.CgroupsPerQOS {
		if err := cm.createNodeAllocatableCgroups(); err != nil {
			return err
		}
		err = cm.qosContainerManager.Start(cm.GetNodeAllocatableAbsolute, activePods)
		if err != nil {
			return fmt.Errorf("failed to initialize top level QOS containers: %v", err)
		}
	}

	// Enforce Node Allocatable (if required)
	if err := cm.enforceNodeAllocatableCgroups(); err != nil {
		return err
	}

	systemContainers := []*systemContainer{}

	if cm.SystemCgroupsName != "" {
		if cm.SystemCgroupsName == "/" {
			return fmt.Errorf("system container cannot be root (\"/\")")
		}
		cont, err := newSystemCgroups(cm.SystemCgroupsName)
		if err != nil {
			return err
		}
		cont.ensureStateFunc = func(manager cgroups.Manager) error {
			return ensureSystemCgroups("/", manager)
		}
		systemContainers = append(systemContainers, cont)
	}

	if cm.KubeletCgroupsName != "" {
		cont, err := newSystemCgroups(cm.KubeletCgroupsName)
		if err != nil {
			return err
		}

		cont.ensureStateFunc = func(_ cgroups.Manager) error {
			return ensureProcessInContainerWithOOMScore(os.Getpid(), int(cm.KubeletOOMScoreAdj), cont.manager)
		}
		systemContainers = append(systemContainers, cont)
	} else {
		cm.periodicTasks = append(cm.periodicTasks, func() {
			if err := ensureProcessInContainerWithOOMScore(os.Getpid(), int(cm.KubeletOOMScoreAdj), nil); err != nil {
				klog.ErrorS(err, "Failed to ensure process in container with oom score")
				return
			}
			cont, err := getContainer(os.Getpid())
			if err != nil {
				klog.ErrorS(err, "Failed to find cgroups of kubelet")
				return
			}
			cm.Lock()
			defer cm.Unlock()

			cm.KubeletCgroupsName = cont
		})
	}

	cm.systemContainers = systemContainers
	return nil
}

func (cm *ContainerManagerImpl) GetNodeConfig() NodeConfig {
	cm.RLock()
	defer cm.RUnlock()
	return cm.NodeConfig
}

// GetPodCgroupRoot returns the literal cgroupfs value for the cgroup containing all pods.
func (cm *ContainerManagerImpl) GetPodCgroupRoot() string {
	return cm.cgroupManager.Name(cm.cgroupRoot)
}

func (cm *ContainerManagerImpl) GetMountedSubsystems() *CgroupSubsystems {
	return cm.subsystems
}

func (cm *ContainerManagerImpl) GetQOSContainersInfo() QOSContainersInfo {
	return cm.qosContainerManager.GetQOSContainersInfo()
}

func (cm *ContainerManagerImpl) UpdateQOSCgroups() error {
	return cm.qosContainerManager.UpdateCgroups()
}

func (cm *ContainerManagerImpl) Status() Status {
	cm.RLock()
	defer cm.RUnlock()
	return cm.status
}

func (cm *ContainerManagerImpl) Start(node *v1.Node,
	activePods ActivePodsFunc,
	sourcesReady config.SourcesReady,
	podStatusProvider status.PodStatusProvider,
	runtimeService internalapi.RuntimeService,
	localStorageCapacityIsolation bool,
) error {
	ctx := context.Background()

	// Initialize CPU manager
	containerMap := buildContainerMapFromRuntime(ctx, runtimeService) // ✅
	err := cm.cpuManager.Start(cpumanager.ActivePodsFunc(activePods), sourcesReady, podStatusProvider, runtimeService, containerMap)
	if err != nil {
		return fmt.Errorf("start cpu manager error: %v", err)
	}

	// Initialize memory manager
	if utilfeature.DefaultFeatureGate.Enabled(kubefeatures.MemoryManager) {
		containerMap := buildContainerMapFromRuntime(ctx, runtimeService)
		err := cm.memoryManager.Start(memorymanager.ActivePodsFunc(activePods), sourcesReady, podStatusProvider, runtimeService, containerMap)
		if err != nil {
			return fmt.Errorf("start memory manager error: %v", err)
		}
	}

	// cache the node Info including resource capacity and
	// allocatable of the node
	cm.nodeInfo = node

	if localStorageCapacityIsolation { // 启用本地临时存储隔离功能
		rootfs, err := cm.cadvisorInterface.RootFsInfo() //获取文件系统 挂载点对应磁盘的使用情况
		if err != nil {
			return fmt.Errorf("failed to get rootfs info: %v", err)
		}
		for rName, rCap := range cadvisor.EphemeralStorageCapacityFromFsInfo(rootfs) {
			cm.capacity[rName] = rCap
		}
	}

	// 确保节点可分配配置是有效的.
	if err := cm.validateNodeAllocatable(); err != nil {
		return err
	}

	// Setup the node
	if err := cm.setupNode(activePods); err != nil {
		return err
	}

	// Don't run a background thread if there are no ensureStateFuncs.
	hasEnsureStateFuncs := false
	for _, cont := range cm.systemContainers {
		if cont.ensureStateFunc != nil {
			hasEnsureStateFuncs = true
			break
		}
	}
	if hasEnsureStateFuncs {
		// Run ensure state functions every minute.
		go wait.Until(func() {
			for _, cont := range cm.systemContainers {
				if cont.ensureStateFunc != nil {
					if err := cont.ensureStateFunc(cont.manager); err != nil {
						klog.InfoS("Failed to ensure state", "containerName", cont.name, "err", err)
					}
				}
			}
		}, time.Minute, wait.NeverStop)

	}

	if len(cm.periodicTasks) > 0 {
		go wait.Until(func() {
			for _, task := range cm.periodicTasks {
				if task != nil {
					task()
				}
			}
		}, 5*time.Minute, wait.NeverStop)
	}

	// Starts device manager.
	if err := cm.DeviceManager.Start(devicemanager.ActivePodsFunc(activePods), sourcesReady); err != nil {
		return err
	}

	return nil
}

func (cm *ContainerManagerImpl) GetPluginRegistrationHandler() cache.PluginHandler {
	return cm.DeviceManager.GetWatcherHandler()
}

// TODO: move the GetResources logic to PodContainerManager.
func (cm *ContainerManagerImpl) GetResources(pod *v1.Pod, container *v1.Container) (*kubecontainer.RunContainerOptions, error) {
	opts := &kubecontainer.RunContainerOptions{}
	if cm.draManager != nil {
		resOpts, err := cm.PrepareResources(pod, container)
		if err != nil {
			return nil, err
		}
		opts.Annotations = append(opts.Annotations, resOpts.Annotations...)
	}
	// Allocate should already be called during predicateAdmitHandler.Admit(),
	// just try to fetch device runtime information from cached state here
	// admit() 期间应该已经调用了Allocate,只是尝试从这里的缓存状态获取设备运行时信息
	devOpts, err := cm.DeviceManager.GetDeviceRunContainerOptions(pod, container)
	if err != nil {
		return nil, err
	} else if devOpts == nil {
		return opts, nil
	}
	opts.Devices = append(opts.Devices, devOpts.Devices...)
	opts.Mounts = append(opts.Mounts, devOpts.Mounts...)
	opts.Envs = append(opts.Envs, devOpts.Envs...)
	opts.Annotations = append(opts.Annotations, devOpts.Annotations...)
	return opts, nil
}

func (cm *ContainerManagerImpl) UpdatePluginResources(node *schedulerframework.NodeInfo, attrs *lifecycle.PodAdmitAttributes) error {
	return cm.DeviceManager.UpdatePluginResources(node, attrs)
}

// GetAllocateResourcesPodAdmitHandler 检查有创建 pod 所需要的资源
func (cm *ContainerManagerImpl) GetAllocateResourcesPodAdmitHandler() lifecycle.PodAdmitHandler {
	if utilfeature.DefaultFeatureGate.Enabled(kubefeatures.TopologyManager) {
		return cm.TopologyManager // 默认开启
	}
	return cm.TopologyManager // 默认开启,已修改代码
}

func (cm *ContainerManagerImpl) SystemCgroupsLimit() v1.ResourceMap {
	cpuLimit := int64(0)

	// Sum up resources of all external containers.
	for _, cont := range cm.systemContainers {
		cpuLimit += cont.cpuMillicores
	}

	return v1.ResourceMap{
		v1.ResourceCPU: *resource.NewMilliQuantity(
			cpuLimit,
			resource.DecimalSI),
	}
}

// ✅
func buildContainerMapFromRuntime(ctx context.Context, runtimeService internalapi.RuntimeService) containermap.ContainerMap {
	podSandboxMap := make(map[string]string)
	podSandboxList, _ := runtimeService.ListPodSandbox(ctx, nil)
	for _, p := range podSandboxList {
		podSandboxMap[p.Id] = p.Metadata.Uid
	}

	containerMap := containermap.NewContainerMap()
	containerList, _ := runtimeService.ListContainers(ctx, nil)
	for _, c := range containerList {
		if _, exists := podSandboxMap[c.PodSandboxId]; !exists {
			klog.InfoS("no PodSandBox found for the container", "podSandboxId", c.PodSandboxId, "containerName", c.Metadata.Name, "containerId", c.Id)
			continue
		}
		containerMap.Add(podSandboxMap[c.PodSandboxId], c.Metadata.Name, c.Id)
	}

	return containerMap
}

func isProcessRunningInHost(pid int) (bool, error) {
	// Get init pid namespace.
	initPidNs, err := os.Readlink("/proc/1/ns/pid")
	if err != nil {
		return false, fmt.Errorf("failed to find pid namespace of init process")
	}
	klog.V(10).InfoS("Found init PID namespace", "namespace", initPidNs)
	processPidNs, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
	if err != nil {
		return false, fmt.Errorf("failed to find pid namespace of process %q", pid)
	}
	klog.V(10).InfoS("Process info", "pid", pid, "namespace", processPidNs)
	return initPidNs == processPidNs, nil
}

func ensureProcessInContainerWithOOMScore(pid int, oomScoreAdj int, manager cgroups.Manager) error {
	if runningInHost, err := isProcessRunningInHost(pid); err != nil {
		// Err on the side of caution. Avoid moving the docker daemon unless we are able to identify its context.
		return err
	} else if !runningInHost {
		// Process is running inside a container. Don't touch that.
		klog.V(2).InfoS("PID is not running in the host namespace", "pid", pid)
		return nil
	}

	var errs []error
	if manager != nil {
		cont, err := getContainer(pid)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to find container of PID %d: %v", pid, err))
		}

		name := ""
		cgroups, err := manager.GetCgroups()
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to get cgroups for %d: %v", pid, err))
		} else {
			name = cgroups.Name
		}

		if cont != name {
			err = manager.Apply(pid)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to move PID %d (in %q) to %q: %v", pid, cont, name, err))
			}
		}
	}

	// Also apply oom-score-adj to processes
	oomAdjuster := oom.NewOOMAdjuster()
	klog.V(5).InfoS("Attempting to apply oom_score_adj to process", "oomScoreAdj", oomScoreAdj, "pid", pid)
	if err := oomAdjuster.ApplyOOMScoreAdj(pid, oomScoreAdj); err != nil {
		klog.V(3).InfoS("Failed to apply oom_score_adj to process", "oomScoreAdj", oomScoreAdj, "pid", pid, "err", err)
		errs = append(errs, fmt.Errorf("failed to apply oom score %d to PID %d: %v", oomScoreAdj, pid, err))
	}
	return utilerrors.NewAggregate(errs)
}

// getContainer returns the cgroup associated with the specified pid.
// It enforces a unified hierarchy for memory and cpu cgroups.
// On systemd environments, it uses the name=systemd cgroup for the specified pid.
func getContainer(pid int) (string, error) {
	cgs, err := cgroups.ParseCgroupFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}

	if cgroups.IsCgroup2UnifiedMode() {
		c, found := cgs[""]
		if !found {
			return "", cgroups.NewNotFoundError("unified")
		}
		return c, nil
	}

	cpu, found := cgs["cpu"]
	if !found {
		return "", cgroups.NewNotFoundError("cpu")
	}
	memory, found := cgs["memory"]
	if !found {
		return "", cgroups.NewNotFoundError("memory")
	}

	// since we use this container for accounting, we need to ensure its a unified hierarchy.
	if cpu != memory {
		return "", fmt.Errorf("cpu and memory cgroup hierarchy not unified.  cpu: %s, memory: %s", cpu, memory)
	}

	// on systemd, every pid is in a unified cgroup hierarchy (name=systemd as seen in systemd-cgls)
	// cpu and memory accounting is off by default, users may choose to enable it per unit or globally.
	// users could enable CPU and memory accounting globally via /etc/systemd/system.conf (DefaultCPUAccounting=true DefaultMemoryAccounting=true).
	// users could also enable CPU and memory accounting per unit via CPUAccounting=true and MemoryAccounting=true
	// we only warn if accounting is not enabled for CPU or memory so as to not break local development flows where kubelet is launched in a terminal.
	// for example, the cgroup for the user session will be something like /user.slice/user-X.slice/session-X.scope, but the cpu and memory
	// cgroup will be the closest ancestor where accounting is performed (most likely /) on systems that launch docker containers.
	// as a result, on those systems, you will not get cpu or memory accounting statistics for kubelet.
	// in addition, you would not get memory or cpu accounting for the runtime unless accounting was enabled on its unit (or globally).
	if systemd, found := cgs["name=systemd"]; found {
		if systemd != cpu {
			klog.InfoS("CPUAccounting not enabled for process", "pid", pid)
		}
		if systemd != memory {
			klog.InfoS("MemoryAccounting not enabled for process", "pid", pid)
		}
		return systemd, nil
	}

	return cpu, nil
}

// Ensures the system container is created and all non-kernel threads and process 1
// without a container are moved to it.
//
// The reason of leaving kernel threads at root cgroup is that we don't want to tie the
// execution of these threads with to-be defined /system quota and create priority inversions.
func ensureSystemCgroups(rootCgroupPath string, manager cgroups.Manager) error {
	// Move non-kernel PIDs to the system container.
	// Only keep errors on latest attempt.
	var finalErr error
	for i := 0; i <= 10; i++ {
		allPids, err := cmutil.GetPids(rootCgroupPath)
		if err != nil {
			finalErr = fmt.Errorf("failed to list PIDs for root: %v", err)
			continue
		}

		// Remove kernel pids and other protected PIDs (pid 1, PIDs already in system & kubelet containers)
		pids := make([]int, 0, len(allPids))
		for _, pid := range allPids {
			if pid == 1 || isKernelPid(pid) {
				continue
			}

			pids = append(pids, pid)
		}

		// Check if we have moved all the non-kernel PIDs.
		if len(pids) == 0 {
			return nil
		}

		klog.V(3).InfoS("Moving non-kernel processes", "pids", pids)
		for _, pid := range pids {
			err := manager.Apply(pid)
			if err != nil {
				name := ""
				cgroups, err := manager.GetCgroups()
				if err == nil {
					name = cgroups.Name
				}

				finalErr = fmt.Errorf("failed to move PID %d into the system container %q: %v", pid, name, err)
			}
		}

	}

	return finalErr
}

// Determines whether the specified PID is a kernel PID.
func isKernelPid(pid int) bool {
	// Kernel threads have no associated executable.
	_, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	return err != nil && os.IsNotExist(err)
}

// GetCapacity returns node capacity data for "cpu", "memory", "ephemeral-storage", and "huge-pages*"
// At present this method is only invoked when introspecting ephemeral storage
func (cm *ContainerManagerImpl) GetCapacity(localStorageCapacityIsolation bool) v1.ResourceMap {
	if localStorageCapacityIsolation {
		// We store allocatable ephemeral-storage in the capacity property once we Start() the container manager
		if _, ok := cm.capacity[v1.ResourceEphemeralStorage]; !ok {
			// If we haven't yet stored the capacity for ephemeral-storage, we can try to fetch it directly from cAdvisor,
			if cm.cadvisorInterface != nil {
				rootfs, err := cm.cadvisorInterface.RootFsInfo()
				if err != nil {
					klog.ErrorS(err, "Unable to get rootfs data from cAdvisor interface")
					// If the rootfsinfo retrieval from cAdvisor fails for any reason, fallback to returning the capacity property with no ephemeral storage data
					return cm.capacity
				}
				// We don't want to mutate cm.capacity here so we'll manually construct a v1.ResourceMap from it,
				// and add ephemeral-storage
				capacityWithEphemeralStorage := v1.ResourceMap{}
				for rName, rQuant := range cm.capacity {
					capacityWithEphemeralStorage[rName] = rQuant
				}
				capacityWithEphemeralStorage[v1.ResourceEphemeralStorage] = cadvisor.EphemeralStorageCapacityFromFsInfo(rootfs)[v1.ResourceEphemeralStorage]
				return capacityWithEphemeralStorage
			}
		}
	}
	return cm.capacity
}

func (cm *ContainerManagerImpl) GetDevicePluginResourceCapacity() (v1.ResourceMap, v1.ResourceMap, []string) {
	return cm.DeviceManager.GetCapacity()
}

func (cm *ContainerManagerImpl) GetDevices(podUID, containerName string) []*podresourcesapi.ContainerDevices {
	return containerDevicesFromResourceDeviceInstances(cm.DeviceManager.GetDevices(podUID, containerName))
}

func (cm *ContainerManagerImpl) GetAllocatableDevices() []*podresourcesapi.ContainerDevices {
	return containerDevicesFromResourceDeviceInstances(cm.DeviceManager.GetAllocatableDevices())
}

func (cm *ContainerManagerImpl) GetCPUs(podUID, containerName string) []int64 {
	if cm.cpuManager != nil {
		return cm.cpuManager.GetExclusiveCPUs(podUID, containerName).ToSliceNoSortInt64()
	}
	return []int64{}
}

func (cm *ContainerManagerImpl) GetAllocatableCPUs() []int64 {
	if cm.cpuManager != nil {
		return cm.cpuManager.GetAllocatableCPUs().ToSliceNoSortInt64()
	}
	return []int64{}
}

func (cm *ContainerManagerImpl) GetMemory(podUID, containerName string) []*podresourcesapi.ContainerMemory {
	if cm.memoryManager == nil {
		return []*podresourcesapi.ContainerMemory{}
	}

	return containerMemoryFromBlock(cm.memoryManager.GetMemory(podUID, containerName))
}

func (cm *ContainerManagerImpl) GetAllocatableMemory() []*podresourcesapi.ContainerMemory {
	if cm.memoryManager == nil {
		return []*podresourcesapi.ContainerMemory{}
	}

	return containerMemoryFromBlock(cm.memoryManager.GetAllocatableMemory())
}

func (cm *ContainerManagerImpl) ShouldResetExtendedResourceCapacity() bool {
	return cm.DeviceManager.ShouldResetExtendedResourceCapacity()
}

func (cm *ContainerManagerImpl) UpdateAllocatedDevices() {
	cm.DeviceManager.UpdateAllocatedDevices()
}

func containerMemoryFromBlock(blocks []memorymanagerstate.Block) []*podresourcesapi.ContainerMemory {
	var containerMemories []*podresourcesapi.ContainerMemory

	for _, b := range blocks {
		containerMemory := podresourcesapi.ContainerMemory{
			MemoryType: string(b.Type),
			Size_:      b.Size,
			Topology: &podresourcesapi.TopologyInfo{
				Nodes: []*podresourcesapi.NUMANode{},
			},
		}

		for _, numaNodeID := range b.NUMAAffinity {
			containerMemory.Topology.Nodes = append(containerMemory.Topology.Nodes, &podresourcesapi.NUMANode{ID: int64(numaNodeID)})
		}

		containerMemories = append(containerMemories, &containerMemory)
	}

	return containerMemories
}

func (cm *ContainerManagerImpl) PrepareResources(pod *v1.Pod, container *v1.Container) (*dra.ContainerInfo, error) {
	return cm.draManager.PrepareResources(pod, container)
}

func (cm *ContainerManagerImpl) UnprepareResources(pod *v1.Pod) error {
	return cm.draManager.UnprepareResources(pod)
}

func (cm *ContainerManagerImpl) PodMightNeedToUnprepareResources(UID types.UID) bool {
	if cm.draManager != nil {
		return cm.draManager.PodMightNeedToUnprepareResources(UID)
	}

	return false
}
