/*
Copyright 2022 The Kubernetes Authors.

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

package reconciler

import (
	"fmt"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/types"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/pkg/kubelet/volumemanager/cache"
	"k8s.io/kubernetes/pkg/util/goroutinemap/exponentialbackoff"
	volumepkg "k8s.io/kubernetes/pkg/volume"
	"k8s.io/kubernetes/pkg/volume/util/hostutil"
	"k8s.io/kubernetes/pkg/volume/util/nestedpendingoperations"
	"k8s.io/kubernetes/pkg/volume/util/operationexecutor"
	"k8s.io/mount-utils"
)

// Reconciler （协调器）会定期运行循环,通过触发附加、分离、挂载和卸载操作来协调世界的期望状态和实际状态.
// 需要注意的是,这与attach/detach控制器实现的Reconciler不同.
// 这个Reconciler是为kubelet卷管理器协调状态的,而那个是为attach/detach控制器协调状态的.
type Reconciler interface {
	// Run 启动运行协调循环,周期性地检查应该挂载的卷是否已经挂载,应该卸载的卷是否已经卸载.
	// 如果没有,它会触发挂载/卸载操作来纠正.
	// 如果启用了attach/detach管理,管理器还会检查应该附加的卷是否已经附加,应该分离的卷是否已经分离,并根据需要触发附加/分离操作.
	Run(stopCh <-chan struct{})
	// StatesHasBeenSynced kubelet启动后至少运行一次
	StatesHasBeenSynced() bool
}

func NewReconciler(
	kubeClient clientset.Interface,
	controllerAttachDetachEnabled bool,
	loopSleepDuration time.Duration,
	waitForAttachTimeout time.Duration,
	nodeName types.NodeName,
	desiredStateOfWorld cache.DesiredStateOfWorld,
	actualStateOfWorld cache.ActualStateOfWorld,
	populatorHasAddedPods func() bool,
	operationExecutor operationexecutor.OperationExecutor,
	mounter mount.Interface,
	hostutil hostutil.HostUtils,
	volumePluginMgr *volumepkg.VolumePluginMgr,
	kubeletPodsDir string) Reconciler {
	return &reconciler{
		kubeClient:                    kubeClient,
		controllerAttachDetachEnabled: controllerAttachDetachEnabled,
		loopSleepDuration:             loopSleepDuration, // 100ms
		waitForAttachTimeout:          waitForAttachTimeout,
		nodeName:                      nodeName,
		desiredStateOfWorld:           desiredStateOfWorld,
		actualStateOfWorld:            actualStateOfWorld,
		populatorHasAddedPods:         populatorHasAddedPods,
		operationExecutor:             operationExecutor,
		mounter:                       mounter,
		hostutil:                      hostutil,
		skippedDuringReconstruction:   map[v1.UniqueVolumeName]*globalVolumeInfo{},
		volumePluginMgr:               volumePluginMgr,
		kubeletPodsDir:                kubeletPodsDir,
		timeOfLastSync:                time.Time{},
		volumesFailedReconstruction:   make([]podVolume, 0),
		volumesNeedDevicePath:         make([]v1.UniqueVolumeName, 0),
		volumesNeedReportedInUse:      make([]v1.UniqueVolumeName, 0),
	}
}

type reconciler struct {
	kubeClient                    clientset.Interface
	controllerAttachDetachEnabled bool          // 如果为true,则表示attach/detach控制器负责管理此节点的attach/detach操作,因此卷管理器不应该.
	loopSleepDuration             time.Duration // 循环执行之间的睡眠时间
	waitForAttachTimeout          time.Duration // Mount函数将等待卷附加的时间
	nodeName                      types.NodeName
	desiredStateOfWorld           cache.DesiredStateOfWorld
	actualStateOfWorld            cache.ActualStateOfWorld
	populatorHasAddedPods         func() bool                         // 检查器,用于检查populator是否已经至少一次将pod添加到desiredStateOfWorld缓存中（在源准备就绪之前,可能会缺少pod）.
	operationExecutor             operationexecutor.OperationExecutor // 用于安全地触发attach/detach/mount/unmount操作（防止在同一卷上触发多个操作）
	mounter                       mount.Interface
	hostutil                      hostutil.HostUtils
	volumePluginMgr               *volumepkg.VolumePluginMgr
	skippedDuringReconstruction   map[v1.UniqueVolumeName]*globalVolumeInfo
	kubeletPodsDir                string
	timeOfLastSync                time.Time
	volumesFailedReconstruction   []podVolume
	volumesNeedDevicePath         []v1.UniqueVolumeName
	volumesNeedReportedInUse      []v1.UniqueVolumeName
}

func (rc *reconciler) Run(stopCh <-chan struct{}) {
	if utilfeature.DefaultFeatureGate.Enabled(features.SELinuxMountReadWriteOncePod) {
		rc.runNew(stopCh)
		return
	}
	//go vm.reconciler.Run(stopCh)
	rc.runOld(stopCh)
}

func (rc *reconciler) unmountDetachDevices() {
	for _, attachedVolume := range rc.actualStateOfWorld.GetUnmountedVolumes() {
		// Check IsOperationPending to avoid marking a volume as detached if it's in the process of mounting.
		if !rc.desiredStateOfWorld.VolumeExists(attachedVolume.VolumeName, attachedVolume.SELinuxMountContext) &&
			!rc.operationExecutor.IsOperationPending(attachedVolume.VolumeName, nestedpendingoperations.EmptyUniquePodName, nestedpendingoperations.EmptyNodeName) {
			if attachedVolume.DeviceMayBeMounted() {
				// Volume is globally mounted to device, unmount it
				klog.V(5).InfoS(attachedVolume.GenerateMsgDetailed("Starting operationExecutor.UnmountDevice", ""))
				err := rc.operationExecutor.UnmountDevice(
					attachedVolume.AttachedVolume, rc.actualStateOfWorld, rc.hostutil)
				if err != nil && !isExpectedError(err) {
					klog.ErrorS(err, attachedVolume.GenerateErrorDetailed(fmt.Sprintf("operationExecutor.UnmountDevice failed (controllerAttachDetachEnabled %v)", rc.controllerAttachDetachEnabled), err).Error())
				}
				if err == nil {
					klog.InfoS(attachedVolume.GenerateMsgDetailed("operationExecutor.UnmountDevice started", ""))
				}
			} else {
				// Volume is attached to node, detach it
				// Kubelet not responsible for detaching or this volume has a non-attachable volume plugin.
				if rc.controllerAttachDetachEnabled || !attachedVolume.PluginIsAttachable {
					rc.actualStateOfWorld.MarkVolumeAsDetached(attachedVolume.VolumeName, attachedVolume.NodeName)
					klog.InfoS(attachedVolume.GenerateMsgDetailed("Volume detached", fmt.Sprintf("DevicePath %q", attachedVolume.DevicePath)))
				} else {
					// Only detach if kubelet detach is enabled
					klog.V(5).InfoS(attachedVolume.GenerateMsgDetailed("Starting operationExecutor.DetachVolume", ""))
					err := rc.operationExecutor.DetachVolume(
						attachedVolume.AttachedVolume, false /* verifySafeToDetach */, rc.actualStateOfWorld)
					if err != nil && !isExpectedError(err) {
						klog.ErrorS(err, attachedVolume.GenerateErrorDetailed(fmt.Sprintf("operationExecutor.DetachVolume failed (controllerAttachDetachEnabled %v)", rc.controllerAttachDetachEnabled), err).Error())
					}
					if err == nil {
						klog.InfoS(attachedVolume.GenerateMsgDetailed("operationExecutor.DetachVolume started", ""))
					}
				}
			}
		}
	}
}

// ----------------------------------------------------------------------------------------------------------------

func (rc *reconciler) mountAttachedVolumes(volumeToMount cache.VolumeToMount, podExistError error) { // ✅
	// 卷没有被挂载,或者已经被挂载,但需要重新挂载.
	remountingLogStr := ""
	isRemount := cache.IsRemountRequiredError(podExistError)
	if isRemount {
		remountingLogStr = "Volume is already mounted to pod, but remount was requested."
	}
	klog.V(4).InfoS(volumeToMount.GenerateMsgDetailed("Starting operationExecutor.MountVolume", remountingLogStr), "pod", klog.KObj(volumeToMount.Pod))
	err := rc.operationExecutor.MountVolume(rc.waitForAttachTimeout, volumeToMount.VolumeToMount, rc.actualStateOfWorld, isRemount)
	if err != nil && !isExpectedError(err) {
		klog.ErrorS(err, volumeToMount.GenerateErrorDetailed(fmt.Sprintf("operationExecutor.MountVolume failed (controllerAttachDetachEnabled %v)", rc.controllerAttachDetachEnabled), err).Error(), "pod", klog.KObj(volumeToMount.Pod))
	}
	if err == nil {
		if remountingLogStr == "" {
			klog.V(1).InfoS(volumeToMount.GenerateMsgDetailed("operationExecutor.MountVolume started", remountingLogStr), "pod", klog.KObj(volumeToMount.Pod))
		} else {
			klog.V(5).InfoS(volumeToMount.GenerateMsgDetailed("operationExecutor.MountVolume started", remountingLogStr), "pod", klog.KObj(volumeToMount.Pod))
		}
	}
}

func (rc *reconciler) unmountVolumes() { // ✅
	//在挂载之前触发卸载操作,这样一个卷如果被一个被删除的pod所引用,现在又被另一个pod所引用,
	//那么它会先从第一个pod中卸载,然后再挂载到新的pod中.这是为了避免数据损坏或数据丢失的情况.

	// Ensure volumes that should be unmounted are unmounted.
	for _, mountedVolume := range rc.actualStateOfWorld.GetAllMountedVolumes() {
		if !rc.desiredStateOfWorld.PodExistsInVolume(mountedVolume.PodName, mountedVolume.VolumeName, mountedVolume.SELinuxMountContext) {
			// Volume is mounted, unmount it
			klog.V(5).InfoS(mountedVolume.GenerateMsgDetailed("Starting operationExecutor.UnmountVolume", ""))
			// /var/lib/kubelet/pods
			err := rc.operationExecutor.UnmountVolume(mountedVolume.MountedVolume, rc.actualStateOfWorld, rc.kubeletPodsDir) // ✅
			if err != nil && !isExpectedError(err) {
				klog.ErrorS(err, mountedVolume.GenerateErrorDetailed(fmt.Sprintf("operationExecutor.UnmountVolume failed (controllerAttachDetachEnabled %v)", rc.controllerAttachDetachEnabled), err).Error())
			}
			if err == nil {
				klog.InfoS(mountedVolume.GenerateMsgDetailed("operationExecutor.UnmountVolume started", ""))
			}
		}
	}
}

func (rc *reconciler) mountOrAttachVolumes() {
	// Ensure volumes that should be attached/mounted are attached/mounted.
	for _, volumeToMount := range rc.desiredStateOfWorld.GetVolumesToMount() {
		// PodExistsInVolume所返回的err决定了下面if的分支走向,configMap热更新走正是下面的其中一个分支,err如果为nil的话,下面分支其实都不执行
		volMounted, devicePath, err := rc.actualStateOfWorld.PodExistsInVolume(
			volumeToMount.PodName,
			volumeToMount.VolumeName,
			volumeToMount.PersistentVolumeSize,
			volumeToMount.SELinuxLabel,
		)
		volumeToMount.DevicePath = devicePath
		if cache.IsSELinuxMountMismatchError(err) {
			// The volume is mounted, but with an unexpected SELinux context.
			// It will get unmounted in unmountVolumes / unmountDetachDevices and
			// then removed from actualStateOfWorld.
			rc.desiredStateOfWorld.AddErrorToPod(volumeToMount.PodName, err.Error())
			continue
		} else if cache.IsVolumeNotAttachedError(err) { // 挂载失败
			// kubelet等待其他程序（例如一些控制器）将卷attach到当前节点
			rc.waitForVolumeAttach(volumeToMount) // ✅
		} else if !volMounted || cache.IsRemountRequiredError(err) { // 没有挂载、需要重新挂载
			// 执行挂载的操作(热更新也在此处)
			rc.mountAttachedVolumes(volumeToMount, err) // ✅ 卷没有被挂载,或者已经被挂载,但需要重新挂载.
		} else if cache.IsFSResizeRequiredError(err) { // 需要重新调整卷大小
			fsResizeRequiredErr, _ := err.(cache.FsResizeRequiredError)
			// kubelet对正在使用的卷的文件系统进行扩容
			rc.expandVolume(volumeToMount, fsResizeRequiredErr.CurrentSize) // ✅
		}
	}
}

func (rc *reconciler) waitForVolumeAttach(volumeToMount cache.VolumeToMount) { // ✅
	// controllerAttachDetachEnabled 就是true
	if rc.controllerAttachDetachEnabled || !volumeToMount.PluginIsAttachable {
		// lets not spin a goroutine and unnecessarily trigger exponential backoff if this happens
		if volumeToMount.PluginIsAttachable && !volumeToMount.ReportedInUse {
			klog.V(5).InfoS(volumeToMount.GenerateMsgDetailed("operationExecutor.VerifyControllerAttachedVolume failed", " volume not marked in-use"), "pod", klog.KObj(volumeToMount.Pod))
			return
		}
		// Volume is not attached (or doesn't implement attacher), kubelet attach is disabled, wait
		// for controller to finish attaching volume.
		klog.V(5).InfoS(volumeToMount.GenerateMsgDetailed("Starting operationExecutor.VerifyControllerAttachedVolume", ""), "pod", klog.KObj(volumeToMount.Pod))
		err := rc.operationExecutor.VerifyControllerAttachedVolume(volumeToMount.VolumeToMount, rc.nodeName, rc.actualStateOfWorld) // ✅
		if err != nil && !isExpectedError(err) {
			klog.ErrorS(err, volumeToMount.GenerateErrorDetailed(fmt.Sprintf("operationExecutor.VerifyControllerAttachedVolume failed (controllerAttachDetachEnabled %v)", rc.controllerAttachDetachEnabled), err).Error(), "pod", klog.KObj(volumeToMount.Pod))
		}
		if err == nil {
			klog.InfoS(volumeToMount.GenerateMsgDetailed("operationExecutor.VerifyControllerAttachedVolume started", ""), "pod", klog.KObj(volumeToMount.Pod))
		}
	} else {
		// Volume is not attached to node, kubelet attach is enabled, volume implements an attacher,
		// so attach it
		volumeToAttach := operationexecutor.VolumeToAttach{
			VolumeName: volumeToMount.VolumeName,
			VolumeSpec: volumeToMount.VolumeSpec,
			NodeName:   rc.nodeName,
		}
		klog.V(5).InfoS(volumeToAttach.GenerateMsgDetailed("Starting operationExecutor.AttachVolume", ""), "pod", klog.KObj(volumeToMount.Pod))
		err := rc.operationExecutor.AttachVolume(volumeToAttach, rc.actualStateOfWorld) // ✅
		if err != nil && !isExpectedError(err) {
			klog.ErrorS(err, volumeToMount.GenerateErrorDetailed(fmt.Sprintf("operationExecutor.AttachVolume failed (controllerAttachDetachEnabled %v)", rc.controllerAttachDetachEnabled), err).Error(), "pod", klog.KObj(volumeToMount.Pod))
		}
		if err == nil {
			klog.InfoS(volumeToMount.GenerateMsgDetailed("operationExecutor.AttachVolume started", ""), "pod", klog.KObj(volumeToMount.Pod))
		}
	}
}

func (rc *reconciler) expandVolume(volumeToMount cache.VolumeToMount, currentSize resource.Quantity) {
	klog.V(4).InfoS(volumeToMount.GenerateMsgDetailed("Starting operationExecutor.ExpandInUseVolume", ""), "pod", klog.KObj(volumeToMount.Pod))
	err := rc.operationExecutor.ExpandInUseVolume(volumeToMount.VolumeToMount, rc.actualStateOfWorld, currentSize)

	if err != nil && !isExpectedError(err) {
		klog.ErrorS(err, volumeToMount.GenerateErrorDetailed("operationExecutor.ExpandInUseVolume failed", err).Error(), "pod", klog.KObj(volumeToMount.Pod))
	}

	if err == nil {
		klog.V(4).InfoS(volumeToMount.GenerateMsgDetailed("operationExecutor.ExpandInUseVolume started", ""), "pod", klog.KObj(volumeToMount.Pod))
	}
}

// ignore nestedpendingoperations.IsAlreadyExists and exponentialbackoff.IsExponentialBackoff errors, they are expected.
func isExpectedError(err error) bool {
	return nestedpendingoperations.IsAlreadyExists(err) || exponentialbackoff.IsExponentialBackoff(err) || operationexecutor.IsMountFailedPreconditionError(err)
}
