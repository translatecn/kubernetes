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

package volumemanager

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/klog/v2"
	"k8s.io/mount-utils"

	v1 "k8s.io/api/core/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
	csitrans "k8s.io/csi-translation-lib"
	"k8s.io/kubernetes/pkg/kubelet/config"
	"k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/pod"
	"k8s.io/kubernetes/pkg/kubelet/volumemanager/cache"
	"k8s.io/kubernetes/pkg/kubelet/volumemanager/metrics"
	"k8s.io/kubernetes/pkg/kubelet/volumemanager/populator"
	"k8s.io/kubernetes/pkg/kubelet/volumemanager/reconciler"
	"k8s.io/kubernetes/pkg/volume"
	"k8s.io/kubernetes/pkg/volume/csimigration"
	"k8s.io/kubernetes/pkg/volume/util"
	"k8s.io/kubernetes/pkg/volume/util/hostutil"
	"k8s.io/kubernetes/pkg/volume/util/operationexecutor"
	"k8s.io/kubernetes/pkg/volume/util/types"
	"k8s.io/kubernetes/pkg/volume/util/volumepathhandler"
)

const (
	reconcilerLoopSleepPeriod                             = 100 * time.Millisecond // 调解器循环在执行之间等待的时间
	desiredStateOfWorldPopulatorLoopSleepPeriod           = 100 * time.Millisecond // 循环在执行之间等待的时间
	desiredStateOfWorldPopulatorGetPodStatusRetryDuration = 2 * time.Second        // 循环在调用containerruntime.GetPodStatus之间等待的时间,以防过于频繁地调用

	// WaitForAttachAndMount 调用将等待指定的Pod中所有卷被附加和挂载的最长时间.
	// 即使云操作可能需要几分钟才能完成,我们也将超时设置为2分钟,因为kubelet将在下一个同步迭代中重试.
	// 如果需要（例如,对Pod的删除请求）,这将释放与Pod相关联的goroutine以处理更新.该值略微偏离2分钟,以使由于此常量而导致的超时可识别.
	podAttachAndMountTimeout       = 2*time.Minute + 3*time.Second
	podAttachAndMountRetryInterval = 300 * time.Millisecond // GetVolumesForPod调用等待重试的时间

	//operationexecutor.Mount 调用等待卷附加的最长时间.将其设置为10分钟,因为我们已经看到在某些情况下,某些卷插件的附加操作需要几分钟才能完成.
	//在等待此操作期间,它仅会阻止同一设备上的其他操作,不会影响其他设备.
	waitForAttachTimeout = 10 * time.Minute
)

// VolumeManager 是一个接口,运行一组异步循环,根据在此节点上调度的Pod确定哪些卷需要附加/挂载/卸载/分离并使其生效.
type VolumeManager interface {
	// Run 启动卷管理器及其控制的所有异步循环.
	Run(sourcesReady config.SourcesReady, stopCh <-chan struct{})
	// WaitForAttachAndMount 处理指定Pod中引用的卷并阻塞,直到它们全部附加和挂载（反映在世界的实际状态中）.
	WaitForAttachAndMount(pod *v1.Pod) error
	// WaitForUnmount 处理指定Pod中引用的卷并阻塞,直到它们全部卸载（反映在实际状态的世界中）.
	WaitForUnmount(pod *v1.Pod) error
	// GetMountedVolumesForPod 返回一个 VolumeMap,其中包含指定Pod成功挂载的卷.映射中的键是 pod.Spec.Volumes[x].Name
	// 如果Pod没有卷,则返回一个空的VolumeMap.
	GetMountedVolumesForPod(podName types.UniquePodName) container.VolumeMap
	// GetPossiblyMountedVolumesForPod 返回一个VolumeMap,其中包含指定Pod 已成功附加挂载或“不确定”的卷,即卷插件可能正在挂载它们.
	// 映射中的键是 （即pod.Spec.Volumes[x].Name）.如果Pod没有卷,则返回一个空的VolumeMap.
	GetPossiblyMountedVolumesForPod(podName types.UniquePodName) container.VolumeMap
	// GetExtraSupplementalGroupsForPod 返回Pod的额外补充组列表.这些额外的补充组来自于Pod依赖的持久卷上的注释.
	GetExtraSupplementalGroupsForPod(pod *v1.Pod) []int64
	// GetVolumesInUse 返回所有实现volume.Attacher接口且根据世界的实际和期望状态缓存当前正在使用的卷列表.
	// 一旦将卷添加到期望状态的世界中,表示它应该附加到此节点并保持“正在使用”,直到从期望状态和实际状态中同时删除或卸载为止（在实际状态中表示）.
	GetVolumesInUse() []v1.UniqueVolumeName
	// ReconcilerStatesHasBeenSynced 仅在调谐器中实际状态至少同步一次之后返回true,以便安全地更新从实际状态检索的已挂载卷列表.
	ReconcilerStatesHasBeenSynced() bool
	// VolumeIsAttached 如果给定卷已附加到此节点,则返回true.
	VolumeIsAttached(volumeName v1.UniqueVolumeName) bool
	// MarkVolumesAsReportedInUse 将指定的卷  标记为已成功报告为“正在使用”节点的卷状态.
	MarkVolumesAsReportedInUse(volumesReportedAsInUse []v1.UniqueVolumeName)
}

// podStateProvider can determine if a pod is going to be terminated
type podStateProvider interface {
	ShouldPodContainersBeTerminating(k8stypes.UID) bool
	ShouldPodRuntimeBeRemoved(k8stypes.UID) bool
}

// NewVolumeManager kubeClient是DesiredStateOfWorldPopulator使用的kube API客户端,用于与API服务器通信以获取PV和PVC对象.
// volumePluginMgr -  用于访问卷插件的卷插件管理器.必须预先初始化.
func NewVolumeManager(
	controllerAttachDetachEnabled bool,
	nodeName k8stypes.NodeName,
	podManager pod.Manager,
	podStateProvider podStateProvider,
	kubeClient clientset.Interface,
	volumePluginMgr *volume.VolumePluginMgr,
	kubeContainerRuntime container.Runtime,
	mounter mount.Interface,
	hostutil hostutil.HostUtils,
	kubeletPodsDir string,
	recorder record.EventRecorder,
	keepTerminatedPodVolumes bool,
	blockVolumePathHandler volumepathhandler.BlockVolumePathHandler) VolumeManager {

	seLinuxTranslator := util.NewSELinuxLabelTranslator()
	vm := &volumeManager{
		kubeClient:          kubeClient,
		volumePluginMgr:     volumePluginMgr, // ✅
		desiredStateOfWorld: cache.NewDesiredStateOfWorld(volumePluginMgr, seLinuxTranslator),
		actualStateOfWorld:  cache.NewActualStateOfWorld(nodeName, volumePluginMgr),
		operationExecutor: operationexecutor.NewOperationExecutor(operationexecutor.NewOperationGenerator(
			kubeClient,
			volumePluginMgr, // ✅
			recorder,
			blockVolumePathHandler)),
	}

	intreeToCSITranslator := csitrans.New()
	csiMigratedPluginManager := csimigration.NewPluginManager(intreeToCSITranslator, utilfeature.DefaultFeatureGate)

	vm.intreeToCSITranslator = intreeToCSITranslator
	vm.csiMigratedPluginManager = csiMigratedPluginManager
	vm.desiredStateOfWorldPopulator = populator.NewDesiredStateOfWorldPopulator(
		kubeClient,
		desiredStateOfWorldPopulatorLoopSleepPeriod,
		desiredStateOfWorldPopulatorGetPodStatusRetryDuration,
		podManager,
		podStateProvider,
		vm.desiredStateOfWorld,
		vm.actualStateOfWorld,
		kubeContainerRuntime,
		keepTerminatedPodVolumes,
		csiMigratedPluginManager,
		intreeToCSITranslator,
		volumePluginMgr)
	vm.reconciler = reconciler.NewReconciler(
		kubeClient,
		controllerAttachDetachEnabled,
		reconcilerLoopSleepPeriod,
		waitForAttachTimeout,
		nodeName,
		vm.desiredStateOfWorld,
		vm.actualStateOfWorld,
		vm.desiredStateOfWorldPopulator.HasAddedPods,
		vm.operationExecutor,
		mounter,
		hostutil,
		volumePluginMgr,
		kubeletPodsDir)

	return vm
}

// volumeManager implements the VolumeManager interface
type volumeManager struct {
	kubeClient                   clientset.Interface                    // kube API客户端,用于与API服务器通信以获取PV和PVC对象
	volumePluginMgr              *volume.VolumePluginMgr                // 用于访问卷插件的卷插件管理器.必须预先初始化.
	desiredStateOfWorld          cache.DesiredStateOfWorld              // 预期状态,volume需要被attach,哪些pods引用这个volume
	actualStateOfWorld           cache.ActualStateOfWorld               // 实际状态,volume已经被attach 哪个node,哪个pod mount volume
	operationExecutor            operationexecutor.OperationExecutor    // 用于启动异步附加、分离、挂载和卸载操作.
	reconciler                   reconciler.Reconciler                  // 运行异步周期性循环以通过使用operationExecutor触发附加、分离、挂载和卸载操作来协调desiredStateOfWorld和actualStateOfWorld.
	desiredStateOfWorldPopulator populator.DesiredStateOfWorldPopulator // 运行异步周期性循环,使用kubelet PodManager填充desiredStateOfWorld.
	csiMigratedPluginManager     csimigration.PluginManager             // 跟踪插件的CSI迁移状态.
	intreeToCSITranslator        csimigration.InTreeToCSITranslator     // 将in-tree卷规范翻译为CSI.
}

func (vm *volumeManager) GetMountedVolumesForPod(podName types.UniquePodName) container.VolumeMap {
	podVolumes := make(container.VolumeMap)
	for _, mountedVolume := range vm.actualStateOfWorld.GetMountedVolumesForPod(podName) {
		podVolumes[mountedVolume.OuterVolumeSpecName] = container.VolumeInfo{
			Mounter:             mountedVolume.Mounter,
			BlockVolumeMapper:   mountedVolume.BlockVolumeMapper,
			ReadOnly:            mountedVolume.VolumeSpec.ReadOnly,
			InnerVolumeSpecName: mountedVolume.InnerVolumeSpecName,
		}
	}
	return podVolumes
}

func (vm *volumeManager) GetPossiblyMountedVolumesForPod(podName types.UniquePodName) container.VolumeMap {
	podVolumes := make(container.VolumeMap)
	for _, mountedVolume := range vm.actualStateOfWorld.GetPossiblyMountedVolumesForPod(podName) {
		podVolumes[mountedVolume.OuterVolumeSpecName] = container.VolumeInfo{
			Mounter:             mountedVolume.Mounter,
			BlockVolumeMapper:   mountedVolume.BlockVolumeMapper,
			ReadOnly:            mountedVolume.VolumeSpec.ReadOnly,
			InnerVolumeSpecName: mountedVolume.InnerVolumeSpecName,
		}
	}
	return podVolumes
}

func (vm *volumeManager) GetExtraSupplementalGroupsForPod(pod *v1.Pod) []int64 {
	podName := util.GetUniquePodName(pod)
	supplementalGroups := sets.NewString()

	for _, mountedVolume := range vm.actualStateOfWorld.GetMountedVolumesForPod(podName) {
		if mountedVolume.VolumeGidValue != "" {
			supplementalGroups.Insert(mountedVolume.VolumeGidValue)
		}
	}

	result := make([]int64, 0, supplementalGroups.Len())
	for _, group := range supplementalGroups.List() {
		iGroup, extra := getExtraSupplementalGid(group, pod)
		if !extra {
			continue
		}

		result = append(result, int64(iGroup))
	}

	return result
}

func (vm *volumeManager) GetVolumesInUse() []v1.UniqueVolumeName {
	// Report volumes in desired state of world and actual state of world so
	// that volumes are marked in use as soon as the decision is made that the
	// volume *should* be attached to this node until it is safely unmounted.
	desiredVolumes := vm.desiredStateOfWorld.GetVolumesToMount()
	allAttachedVolumes := vm.actualStateOfWorld.GetAttachedVolumes()
	volumesToReportInUse := make([]v1.UniqueVolumeName, 0, len(desiredVolumes)+len(allAttachedVolumes))
	desiredVolumesMap := make(map[v1.UniqueVolumeName]bool, len(desiredVolumes)+len(allAttachedVolumes))

	for _, volume := range desiredVolumes {
		if volume.PluginIsAttachable {
			if _, exists := desiredVolumesMap[volume.VolumeName]; !exists {
				desiredVolumesMap[volume.VolumeName] = true
				volumesToReportInUse = append(volumesToReportInUse, volume.VolumeName)
			}
		}
	}

	for _, volume := range allAttachedVolumes {
		if volume.PluginIsAttachable {
			if _, exists := desiredVolumesMap[volume.VolumeName]; !exists {
				volumesToReportInUse = append(volumesToReportInUse, volume.VolumeName)
			}
		}
	}

	sort.Slice(volumesToReportInUse, func(i, j int) bool {
		return string(volumesToReportInUse[i]) < string(volumesToReportInUse[j])
	})
	return volumesToReportInUse
}

func (vm *volumeManager) ReconcilerStatesHasBeenSynced() bool {
	return vm.reconciler.StatesHasBeenSynced()
}

func (vm *volumeManager) VolumeIsAttached(
	volumeName v1.UniqueVolumeName) bool {
	return vm.actualStateOfWorld.VolumeExists(volumeName)
}

func (vm *volumeManager) MarkVolumesAsReportedInUse(
	volumesReportedAsInUse []v1.UniqueVolumeName) {
	vm.desiredStateOfWorld.MarkVolumesReportedInUse(volumesReportedAsInUse)
}

func (vm *volumeManager) WaitForAttachAndMount(pod *v1.Pod) error {
	if pod == nil {
		return nil
	}

	expectedVolumes := getExpectedVolumes(pod) // 获取pod 需要绑定哪些 volume
	if len(expectedVolumes) == 0 {
		// No volumes to verify
		return nil
	}

	klog.V(3).InfoS("Waiting for volumes to attach and mount for pod", "pod", klog.KObj(pod))
	uniquePodName := util.GetUniquePodName(pod)

	// Some pods expect to have Setup called over and over again to update.
	// Remount plugins for which this is true. (Atomically updating volumes,
	// like Downward API, depend on this to update the contents of the volume).
	// 一些pod希望一次又一次地调用安装程序来更新.重新挂载符合此要求的插件.(自动更新卷,如 downloadAPI,依赖于此来更新卷的内容).
	vm.desiredStateOfWorldPopulator.ReprocessPod(uniquePodName) // 标记m

	err := wait.PollImmediate(
		podAttachAndMountRetryInterval, // 300ms
		podAttachAndMountTimeout,       // 2m + 3s
		vm.verifyVolumesMountedFunc(uniquePodName, expectedVolumes))

	if err != nil {
		unmountedVolumes := vm.getUnmountedVolumes(uniquePodName, expectedVolumes)
		// Also get unattached volumes for error message
		unattachedVolumes := vm.getUnattachedVolumes(expectedVolumes)

		if len(unmountedVolumes) == 0 {
			return nil
		}

		return fmt.Errorf(
			"unmounted volumes=%v, unattached volumes=%v: %s",
			unmountedVolumes,
			unattachedVolumes,
			err)
	}

	klog.V(3).InfoS("All volumes are attached and mounted for pod", "pod", klog.KObj(pod))
	return nil
}

func (vm *volumeManager) WaitForUnmount(pod *v1.Pod) error {
	if pod == nil {
		return nil
	}

	klog.V(3).InfoS("Waiting for volumes to unmount for pod", "pod", klog.KObj(pod))
	uniquePodName := util.GetUniquePodName(pod)

	vm.desiredStateOfWorldPopulator.ReprocessPod(uniquePodName)

	err := wait.PollImmediate(
		podAttachAndMountRetryInterval,
		podAttachAndMountTimeout,
		vm.verifyVolumesUnmountedFunc(uniquePodName))

	if err != nil {
		var mountedVolumes []string
		for _, v := range vm.actualStateOfWorld.GetMountedVolumesForPod(uniquePodName) {
			mountedVolumes = append(mountedVolumes, v.OuterVolumeSpecName)
		}
		sort.Strings(mountedVolumes)

		if len(mountedVolumes) == 0 {
			return nil
		}

		return fmt.Errorf(
			"mounted volumes=%v: %s",
			mountedVolumes,
			err)
	}

	klog.V(3).InfoS("All volumes are unmounted for pod", "pod", klog.KObj(pod))
	return nil
}

// getUnattachedVolumes returns a list of the volumes that are expected to be attached but
// are not currently attached to the node
func (vm *volumeManager) getUnattachedVolumes(expectedVolumes []string) []string {
	unattachedVolumes := []string{}
	for _, volume := range expectedVolumes {
		if !vm.actualStateOfWorld.VolumeExists(v1.UniqueVolumeName(volume)) {
			unattachedVolumes = append(unattachedVolumes, volume)
		}
	}
	return unattachedVolumes
}

// verifyVolumesMountedFunc returns a method that returns true when all expected
// volumes are mounted.
func (vm *volumeManager) verifyVolumesMountedFunc(podName types.UniquePodName, expectedVolumes []string) wait.ConditionFunc {
	return func() (done bool, err error) {
		if errs := vm.desiredStateOfWorld.PopPodErrors(podName); len(errs) > 0 {
			return true, errors.New(strings.Join(errs, "; "))
		}
		return len(vm.getUnmountedVolumes(podName, expectedVolumes)) == 0, nil
	}
}

// verifyVolumesUnmountedFunc returns a method that is true when there are no mounted volumes for this
// pod.
func (vm *volumeManager) verifyVolumesUnmountedFunc(podName types.UniquePodName) wait.ConditionFunc {
	return func() (done bool, err error) {
		if errs := vm.desiredStateOfWorld.PopPodErrors(podName); len(errs) > 0 {
			return true, errors.New(strings.Join(errs, "; "))
		}
		return len(vm.actualStateOfWorld.GetMountedVolumesForPod(podName)) == 0, nil
	}
}

// getUnmountedVolumes fetches the current list of mounted volumes from
// the actual state of the world, and uses it to process the list of
// expectedVolumes. It returns a list of unmounted volumes.
// The list also includes volume that may be mounted in uncertain state.
func (vm *volumeManager) getUnmountedVolumes(podName types.UniquePodName, expectedVolumes []string) []string {
	mountedVolumes := sets.NewString()
	for _, mountedVolume := range vm.actualStateOfWorld.GetMountedVolumesForPod(podName) {
		mountedVolumes.Insert(mountedVolume.OuterVolumeSpecName)
	}
	return filterUnmountedVolumes(mountedVolumes, expectedVolumes)
}

// filterUnmountedVolumes adds each element of expectedVolumes that is not in
// mountedVolumes to a list of unmountedVolumes and returns it.
func filterUnmountedVolumes(mountedVolumes sets.String, expectedVolumes []string) []string {
	unmountedVolumes := []string{}
	for _, expectedVolume := range expectedVolumes {
		if !mountedVolumes.Has(expectedVolume) {
			unmountedVolumes = append(unmountedVolumes, expectedVolume)
		}
	}
	return unmountedVolumes
}

// ----------------------------------------------------------------------------------------

// getExpectedVolumes returns a list of volumes that must be mounted in order to
// consider the volume setup step for this pod satisfied.
func getExpectedVolumes(pod *v1.Pod) []string {
	mounts, devices, _ := util.GetPodVolumeNames(pod)
	return mounts.Union(devices).UnsortedList() // 并集
}

// getExtraSupplementalGid 函数返回一个额外的辅助 GID 的值,该 GID 由卷上的注释定义,并指示该卷是否定义了Pod尚未请求的GID.
func getExtraSupplementalGid(volumeGidValue string, pod *v1.Pod) (int64, bool) {
	if volumeGidValue == "" {
		return 0, false
	}

	gid, err := strconv.ParseInt(volumeGidValue, 10, 64)
	if err != nil {
		return 0, false
	}

	if pod.Spec.SecurityContext != nil {
		for _, existingGid := range pod.Spec.SecurityContext.SupplementalGroups {
			if gid == int64(existingGid) {
				return 0, false
			}
		}
	}

	return gid, true
}
func (vm *volumeManager) Run(sourcesReady config.SourcesReady, stopCh <-chan struct{}) {
	defer runtime.HandleCrash()

	if vm.kubeClient != nil {
		// start informer for CSIDriver
		go vm.volumePluginMgr.Run(stopCh) // ✅
	}

	go vm.desiredStateOfWorldPopulator.Run(sourcesReady, stopCh) // ✅ 从 apiserver 同步到的pod信息,来更新DesiredStateOfWorld

	klog.V(2).InfoS("The desired_state_of_world populator starts")

	klog.InfoS("Starting Kubelet Volume Manager")
	go vm.reconciler.Run(stopCh) // ✅ 预期状态和实际状态的协调者,负责调整实际状态至预期状态

	metrics.Register(vm.actualStateOfWorld, vm.desiredStateOfWorld, vm.volumePluginMgr)

	<-stopCh
	klog.InfoS("Shutting down Kubelet Volume Manager")
}
