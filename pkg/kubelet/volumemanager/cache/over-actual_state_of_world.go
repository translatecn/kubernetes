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

/*
Package cache implements data structures used by the kubelet volume manager to
keep track of attached volumes and the pods that mounted them.
*/
package cache

import (
	"fmt"
	"sync"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/types"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/pkg/volume"
	"k8s.io/kubernetes/pkg/volume/util"
	"k8s.io/kubernetes/pkg/volume/util/operationexecutor"
	volumetypes "k8s.io/kubernetes/pkg/volume/util/types"
)

// ActualStateOfWorld 此缓存包含卷->Pod,即附加到此节点的所有卷以及经理认为已成功挂载卷的 Pod 集合.
type ActualStateOfWorld interface {
	operationexecutor.ActualStateOfWorldMounterUpdater
	operationexecutor.ActualStateOfWorldAttacherUpdater
	// AddPodToVolume 将给定的 Pod 添加到缓存中的给定卷中,指示已成功将指定卷挂载到指定 Pod.
	// 如果指定卷下已存在具有相同唯一名称的 Pod,则重置 Pod 的 remountRequired 值.
	// 如果卷列表中不存在名称为 volumeName 的卷,则返回错误.
	AddPodToVolume(operationexecutor.MarkVolumeOpts) error
	MarkRemountRequired(podName volumetypes.UniquePodName) // 标记volume 需要重新挂载
	// SetDeviceMountState 为给定卷设置设备挂载状态. DeviceMountUncertain、DeviceGloballyMounted 必须在分离之前从全局挂载点卸载卷.
	SetDeviceMountState(volumeName v1.UniqueVolumeName, deviceMountState operationexecutor.DeviceMountState, devicePath, deviceMountPath, seLinuxMountContext string) error
	// DeletePodFromVolume 从缓存中的给定卷中删除给定 Pod,指示该卷已成功从 Pod 卸载.
	// 如果在指定卷下不存在具有相同唯一名称的 Pod,则不执行任何操作.
	// 如果卷列表中不存在名称为 volumeName 的卷,则返回错误.
	DeletePodFromVolume(podName volumetypes.UniquePodName, volumeName v1.UniqueVolumeName) error
	// DeleteVolume 从缓存中的已附加卷列表中删除给定卷,指示该卷已成功从此节点分离.
	// 如果卷列表中不存在名称为 volumeName 的卷,则不执行任何操作.
	// 如果存在名称为 volumeName 的卷且其已挂载 Pod 的列表不为空,则返回错误.
	DeleteVolume(volumeName v1.UniqueVolumeName) error

	// PodExistsInVolume 如果给定的 Pod 存在于缓存中给定卷的 mountedPods 列表中,则返回 true,
	// 表示该卷已附加到此节点并且 Pod 已成功挂载该卷.
	// 如果在指定卷下不存在具有相同唯一名称的 Pod,则返回 false.
	// 如果卷列表中不存在名称为 volumeName 的卷,则返回 volumeNotAttachedError,指示该卷尚未附加.
	// 如果给定的 volumeName/podName 组合存在但 remountRequired 的值为 true,则返回 remountRequiredError,
	// 指示已成功将给定卷挂载到此 Pod,但应重新挂载以反映引用 Pod 中的更改.像 Downward API 这样的原子更新卷依赖于此以更新卷的内容.
	// 所有卷挂载调用都应该是幂等的,因此不需要更新内容的卷的第二个挂载调用不应失败.
	PodExistsInVolume(podName volumetypes.UniquePodName, volumeName v1.UniqueVolumeName, desiredVolumeSize resource.Quantity, seLinuxLabel string) (bool, string, error)

	// PodRemovedFromVolume 如果给定的Pod在缓存中的已挂载Pod列表中不存在,则PodRemovedFromVolume返回true,表示该Pod已完全卸载了该卷或者从未将卷挂载到该Pod中.
	// 如果该卷已完全挂载或者对于该Pod而言处于不确定的挂载状态,则认为该Pod仍存在于卷管理器的实际世界状态中,并返回false.
	PodRemovedFromVolume(podName volumetypes.UniquePodName, volumeName v1.UniqueVolumeName) bool

	// VolumeExistsWithSpecName returns true if the given volume specified with the
	// volume spec name (a.k.a., InnerVolumeSpecName) exists in the list of
	// volumes that should be attached to this node.
	// If a pod with the same name does not exist under the specified
	// volume, false is returned.
	VolumeExistsWithSpecName(podName volumetypes.UniquePodName, volumeSpecName string) bool

	// VolumeExists returns true if the given volume exists in the list of
	// attached volumes in the cache, indicating the volume is attached to this
	// node.
	VolumeExists(volumeName v1.UniqueVolumeName) bool

	// GetMountedVolumes generates and returns a list of volumes and the pods
	// they are successfully attached and mounted for based on the current
	// actual state of the world.
	GetMountedVolumes() []MountedVolume

	// GetAllMountedVolumes returns list of all possibly mounted volumes including
	// those that are in VolumeMounted state and VolumeMountUncertain state.
	GetAllMountedVolumes() []MountedVolume

	// GetMountedVolumesForPod generates and returns a list of volumes that are
	// successfully attached and mounted for the specified pod based on the
	// current actual state of the world.
	GetMountedVolumesForPod(podName volumetypes.UniquePodName) []MountedVolume

	// GetPossiblyMountedVolumesForPod generates and returns a list of volumes for
	// the specified pod that either are attached and mounted or are "uncertain",
	// i.e. a volume plugin may be mounting the volume right now.
	GetPossiblyMountedVolumesForPod(podName volumetypes.UniquePodName) []MountedVolume

	// GetGloballyMountedVolumes generates and returns a list of all attached
	// volumes that are globally mounted. This list can be used to determine
	// which volumes should be reported as "in use" in the node's VolumesInUse
	// status field. Globally mounted here refers to the shared plugin mount
	// point for the attachable volume from which the pod specific mount points
	// are created (via bind mount).
	GetGloballyMountedVolumes() []AttachedVolume

	// GetUnmountedVolumes generates and returns a list of attached volumes that
	// have no mountedPods. This list can be used to determine which volumes are
	// no longer referenced and may be globally unmounted and detached.
	GetUnmountedVolumes() []AttachedVolume

	// GetAttachedVolumes returns a list of volumes that is known to be attached
	// to the node. This list can be used to determine volumes that are either in-use
	// or have a mount/unmount operation pending.
	GetAttachedVolumes() []AttachedVolume

	// SyncReconstructedVolume 检查 asw 中的 volume.outerVolumeSpecName 字段和从 dsw 中重建的该字段的值是否匹配,如果不匹配,则更新该字段的值为从 dsw 中重建的值.
	SyncReconstructedVolume(volumeName v1.UniqueVolumeName, podName volumetypes.UniquePodName, outerVolumeSpecName string)
	// UpdateReconstructedDevicePath 根据节点（Node）的状态（Status）中的已挂载卷（VolumesAttached）,更新重构卷的设备路径（devicePath）
	// 只有在卷仍然不确定的情况下,才会更新ASW.如果在此期间卷已挂载,则其设备路径必须已通过此类更新进行了修复.
	UpdateReconstructedDevicePath(volumeName v1.UniqueVolumeName, devicePath string)
}

// MountedVolume represents a volume that has successfully been mounted to a pod.
type MountedVolume struct {
	operationexecutor.MountedVolume
}

// AttachedVolume represents a volume that is attached to a node.
type AttachedVolume struct {
	operationexecutor.AttachedVolume

	// DeviceMountState indicates if device has been globally mounted or is not.
	DeviceMountState operationexecutor.DeviceMountState

	// SELinuxMountContext is the context with that the volume is globally mounted
	// (via -o context=XYZ mount option). If empty, the volume is not mounted with
	// "-o context=".
	SELinuxMountContext string
}

// DeviceMayBeMounted returns true if device is mounted in global path or is in
// uncertain state.
func (av AttachedVolume) DeviceMayBeMounted() bool {
	return av.DeviceMountState == operationexecutor.DeviceGloballyMounted || av.DeviceMountState == operationexecutor.DeviceMountUncertain
}

// NewActualStateOfWorld returns a new instance of ActualStateOfWorld.
func NewActualStateOfWorld(
	nodeName types.NodeName,
	volumePluginMgr *volume.VolumePluginMgr) ActualStateOfWorld {
	return &actualStateOfWorld{
		nodeName:                  nodeName,
		attachedVolumes:           make(map[v1.UniqueVolumeName]attachedVolume),
		foundDuringReconstruction: make(map[v1.UniqueVolumeName]map[volumetypes.UniquePodName]types.UID),
		volumePluginMgr:           volumePluginMgr,
	}
}

type actualStateOfWorld struct {
	nodeName                  types.NodeName                                                  // 此节点的名称
	attachedVolumes           map[v1.UniqueVolumeName]attachedVolume                          // 包含kubelet卷管理器认为已成功附加到此节点的卷集.
	foundDuringReconstruction map[v1.UniqueVolumeName]map[volumetypes.UniquePodName]types.UID // 包含在重新启动kubelet时从kubelet根目录中发现的卷.
	volumePluginMgr           *volume.VolumePluginMgr                                         // 用于创建卷插件对象的卷插件管理器.
	sync.RWMutex
}

// kubelet卷管理器认为已成功附加到正在管理的节点的卷.
// 没有实现attacher的卷类型被假定处于这种状态.
type attachedVolume struct {
	volumeName  v1.UniqueVolumeName
	mountedPods map[volumetypes.UniquePodName]mountedPod // 已成功挂载此卷的一组Pod的映射
	// 包含此卷规范的卷规范
	// /var/lib/kubelet/pods/{podUID}/volumes/{escapeQualifiedPluginName}/{volumeSpecName}/
	spec                         *volume.Spec
	pluginName                   string                             // 用于附加和挂载此卷的卷插件的未转义限定名称
	pluginIsAttachable           bool                               // 用于附加和挂载此卷的卷插件是否实现了volume.Attacher接口.
	deviceMountState             operationexecutor.DeviceMountState // 存储信息,告诉我们设备是否全局挂载.
	devicePath                   string                             // 附加卷的节点上的路径,用于可附加卷.
	deviceMountPath              string                             // 附加设备后设备应挂载到的节点上的路径.
	volumeInUseErrorForExpansion bool                               // 指示卷驱动程序先前是否为此卷返回过卷正在使用的错误,此节点上不应重试卷扩展.
	persistentVolumeSize         *resource.Quantity                 // 记录Pod启动时卷的大小或卷扩展操作成功完成后的大小.
	seLinuxMountContext          *string                            // 卷挂载到全局目录的上下文（通过-o context = XYZ挂载选项）.如果为nil,则未挂载卷.如果为"",则卷被挂载而不带有“-o context =”.
}

// The mountedPod object represents a pod for which the kubelet volume manager
// believes the underlying volume has been successfully been mounted.
type mountedPod struct {
	podName           volumetypes.UniquePodName
	podUID            types.UID
	mounter           volume.Mounter
	blockVolumeMapper volume.BlockVolumeMapper
	// /var/lib/kubelet/pods/{podUID}/volumes/{escapeQualifiedPluginName}/{volumeSpecName}/
	volumeSpec *volume.Spec

	// outerVolumeSpecName is the volume.Spec.Name() of the volume as referenced
	// directly in the pod. If the volume was referenced through a persistent
	// volume claim, this contains the volume.Spec.Name() of the persistent
	// volume claim
	outerVolumeSpecName string

	// remountRequired indicates the underlying volume has been successfully
	// mounted to this pod but it should be remounted to reflect changes in the
	// referencing pod.
	// Atomically updating volumes depend on this to update the contents of the
	// volume. All volume mounting calls should be idempotent so a second mount
	// call for volumes that do not need to update contents should not fail.
	remountRequired bool

	// volumeGidValue contains the value of the GID annotation, if present.
	volumeGidValue string

	// volumeMountStateForPod stores state of volume mount for the pod. if it is:
	//   - VolumeMounted: means volume for pod has been successfully mounted
	//   - VolumeMountUncertain: means volume for pod may not be mounted, but it must be unmounted
	volumeMountStateForPod operationexecutor.VolumeMountState

	// seLinuxMountContext is the context with that the volume is mounted to Pod directory
	// (via -o context=XYZ mount option). If nil, the volume is not mounted. If "", the volume is
	// mounted without "-o context=".
	seLinuxMountContext string
}

// CheckAndMarkVolumeAsUncertainViaReconstruction 检查并将卷标记为不确定状态.如果该卷已经存在于实际世界状态中,则不会将其添加到实际世界状态中,以避免覆盖先前存储的任何状态.
// 如果将卷添加到实际世界状态中,则返回true,否则返回false.如果将卷添加到实际世界状态中时出现错误,则返回错误.
func (asw *actualStateOfWorld) CheckAndMarkVolumeAsUncertainViaReconstruction(opts operationexecutor.MarkVolumeOpts) (bool, error) {
	asw.Lock()
	defer asw.Unlock()

	volumeObj, volumeExists := asw.attachedVolumes[opts.VolumeName]
	if !volumeExists {
		return false, nil
	}

	podObj, podExists := volumeObj.mountedPods[opts.PodName]
	if podExists {
		// if volume mount was uncertain we should keep trying to unmount the volume
		if podObj.volumeMountStateForPod == operationexecutor.VolumeMountUncertain {
			return false, nil
		}
		if podObj.volumeMountStateForPod == operationexecutor.VolumeMounted {
			return false, nil
		}
	}

	podName := opts.PodName
	podUID := opts.PodUID
	volumeName := opts.VolumeName
	mounter := opts.Mounter
	blockVolumeMapper := opts.BlockVolumeMapper
	outerVolumeSpecName := opts.OuterVolumeSpecName
	volumeGidValue := opts.VolumeGidVolume
	volumeSpec := opts.VolumeSpec

	podObj = mountedPod{
		podName:                podName,
		podUID:                 podUID,
		mounter:                mounter,
		blockVolumeMapper:      blockVolumeMapper,
		outerVolumeSpecName:    outerVolumeSpecName,
		volumeGidValue:         volumeGidValue,
		volumeSpec:             volumeSpec,
		remountRequired:        false,
		volumeMountStateForPod: operationexecutor.VolumeMountUncertain,
	}

	if mounter != nil {
		// The mounter stored in the object may have old information,
		// use the newest one.
		podObj.mounter = mounter
	}

	asw.attachedVolumes[volumeName].mountedPods[podName] = podObj

	podMap, ok := asw.foundDuringReconstruction[opts.VolumeName]
	if !ok {
		podMap = map[volumetypes.UniquePodName]types.UID{}
	}
	podMap[opts.PodName] = opts.PodUID
	asw.foundDuringReconstruction[opts.VolumeName] = podMap
	return true, nil
}

// CheckAndMarkDeviceUncertainViaReconstruction 仅在设备不在实际世界状态中时才将其添加到该状态中.这样可以避免覆盖之前存储的任何状态.
// 函数只提供设备挂载路径（deviceMountPath）,因为设备路径（devicePath）已经在VerifyControllerAttachedVolume函数中确定
func (asw *actualStateOfWorld) CheckAndMarkDeviceUncertainViaReconstruction(volumeName v1.UniqueVolumeName, deviceMountPath string) bool {
	asw.Lock()
	defer asw.Unlock()

	volumeObj, volumeExists := asw.attachedVolumes[volumeName]
	// CheckAndMarkDeviceUncertainViaReconstruction requires volume to be marked as attached, so if
	// volume does not exist in ASOW or is in any state other than DeviceNotMounted we should return
	if !volumeExists || volumeObj.deviceMountState != operationexecutor.DeviceNotMounted {
		return false
	}

	volumeObj.deviceMountState = operationexecutor.DeviceMountUncertain
	// we are only changing deviceMountPath because devicePath at at this stage is
	// determined from node object.
	volumeObj.deviceMountPath = deviceMountPath
	asw.attachedVolumes[volumeName] = volumeObj
	return true

}

func (asw *actualStateOfWorld) GetVolumeMountState(volumeName v1.UniqueVolumeName, podName volumetypes.UniquePodName) operationexecutor.VolumeMountState {
	asw.RLock()
	defer asw.RUnlock()

	volumeObj, volumeExists := asw.attachedVolumes[volumeName]
	if !volumeExists {
		return operationexecutor.VolumeNotMounted
	}

	podObj, podExists := volumeObj.mountedPods[podName]
	if !podExists {
		return operationexecutor.VolumeNotMounted
	}
	return podObj.volumeMountStateForPod
}

func (asw *actualStateOfWorld) IsVolumeMountedElsewhere(volumeName v1.UniqueVolumeName, podName volumetypes.UniquePodName) bool {
	asw.RLock()
	defer asw.RUnlock()

	volumeObj, volumeExists := asw.attachedVolumes[volumeName]
	if !volumeExists {
		return false
	}

	for _, podObj := range volumeObj.mountedPods {
		if podName != podObj.podName {
			// 将不确定的挂载状态视为已挂载状态,直到挂载状态确定为止
			if podObj.volumeMountStateForPod != operationexecutor.VolumeNotMounted {
				return true
			}
		}
	}
	return false
}

// MarkVolumeAsResized 标记指定卷的文件系统调整大小请求已完成.
func (asw *actualStateOfWorld) MarkVolumeAsResized(volumeName v1.UniqueVolumeName, claimSize *resource.Quantity) bool {
	asw.Lock()
	defer asw.Unlock()

	volumeObj, ok := asw.attachedVolumes[volumeName]
	if ok {
		volumeObj.persistentVolumeSize = claimSize
		asw.attachedVolumes[volumeName] = volumeObj
		return true
	}
	return false
}

func (asw *actualStateOfWorld) SetDeviceMountState(volumeName v1.UniqueVolumeName, deviceMountState operationexecutor.DeviceMountState, devicePath, deviceMountPath, seLinuxMountContext string) error {
	asw.Lock()
	defer asw.Unlock()

	volumeObj, volumeExists := asw.attachedVolumes[volumeName]
	if !volumeExists {
		return fmt.Errorf("no volume with the name %q exists in the list of attached volumes", volumeName)
	}

	volumeObj.deviceMountState = deviceMountState
	volumeObj.deviceMountPath = deviceMountPath
	if devicePath != "" {
		volumeObj.devicePath = devicePath
	}
	if utilfeature.DefaultFeatureGate.Enabled(features.SELinuxMountReadWriteOncePod) {
		if seLinuxMountContext != "" {
			volumeObj.seLinuxMountContext = &seLinuxMountContext
		}
	}
	asw.attachedVolumes[volumeName] = volumeObj
	return nil
}

func (asw *actualStateOfWorld) InitializeClaimSize(volumeName v1.UniqueVolumeName, claimSize *resource.Quantity) {
	asw.Lock()
	defer asw.Unlock()

	volumeObj, ok := asw.attachedVolumes[volumeName]
	// only set volume claim size if claimStatusSize is zero
	// this can happen when volume was rebuilt after kubelet startup
	if ok && volumeObj.persistentVolumeSize == nil {
		volumeObj.persistentVolumeSize = claimSize
		asw.attachedVolumes[volumeName] = volumeObj
	}
}

func (asw *actualStateOfWorld) GetClaimSize(volumeName v1.UniqueVolumeName) *resource.Quantity {
	asw.RLock()
	defer asw.RUnlock()

	volumeObj, ok := asw.attachedVolumes[volumeName]
	if ok {
		return volumeObj.persistentVolumeSize
	}
	return nil
}

func (asw *actualStateOfWorld) PodExistsInVolume(podName volumetypes.UniquePodName, volumeName v1.UniqueVolumeName, desiredVolumeSize resource.Quantity, seLinuxLabel string) (bool, string, error) {
	asw.RLock()
	defer asw.RUnlock()

	volumeObj, volumeExists := asw.attachedVolumes[volumeName]
	if !volumeExists {
		return false, "", newVolumeNotAttachedError(volumeName)
	}

	// The volume exists, check its SELinux context mount option
	if utilfeature.DefaultFeatureGate.Enabled(features.SELinuxMountReadWriteOncePod) {
		if volumeObj.seLinuxMountContext != nil && *volumeObj.seLinuxMountContext != seLinuxLabel {
			fullErr := newSELinuxMountMismatchError(volumeName)
			return false, volumeObj.devicePath, fullErr
		}
	}

	podObj, podExists := volumeObj.mountedPods[podName]
	if podExists {
		// if volume mount was uncertain we should keep trying to mount the volume
		if podObj.volumeMountStateForPod == operationexecutor.VolumeMountUncertain {
			return false, volumeObj.devicePath, nil
		}
		if podObj.remountRequired {
			return true, volumeObj.devicePath, newRemountRequiredError(volumeObj.volumeName, podObj.podName)
		}
		if currentSize, expandVolume := asw.volumeNeedsExpansion(volumeObj, desiredVolumeSize); expandVolume {
			return true, volumeObj.devicePath, newFsResizeRequiredError(volumeObj.volumeName, podObj.podName, currentSize)
		}
	}

	return podExists, volumeObj.devicePath, nil
}

func (asw *actualStateOfWorld) volumeNeedsExpansion(volumeObj attachedVolume, desiredVolumeSize resource.Quantity) (resource.Quantity, bool) {
	//存储卷需要扩展（增加容量）的情况.存储卷的容量是有限的,当存储空间不足时,需要对存储卷进行扩展以增加其容量.
	currentSize := resource.Quantity{}
	if volumeObj.persistentVolumeSize != nil {
		currentSize = volumeObj.persistentVolumeSize.DeepCopy()
	}
	if volumeObj.volumeInUseErrorForExpansion {
		return currentSize, false
	}
	if volumeObj.persistentVolumeSize == nil || desiredVolumeSize.IsZero() {
		return currentSize, false
	}

	if desiredVolumeSize.Cmp(*volumeObj.persistentVolumeSize) > 0 {
		volumePlugin, err := asw.volumePluginMgr.FindNodeExpandablePluginBySpec(volumeObj.spec)
		if err != nil || volumePlugin == nil {
			// Log and continue processing
			klog.InfoS("PodExistsInVolume failed to find expandable plugin",
				"volume", volumeObj.volumeName,
				"volumeSpecName", volumeObj.spec.Name())
			return currentSize, false
		}
		if volumePlugin.RequiresFSResize() {
			return currentSize, true
		}
	}
	return currentSize, false
}

// Compile-time check to ensure volumeNotAttachedError implements the error interface
var _ error = volumeNotAttachedError{}

// volumeNotAttachedError is an error returned when PodExistsInVolume() fails to
// find specified volume in the list of attached volumes.
type volumeNotAttachedError struct {
	volumeName v1.UniqueVolumeName
}

func (err volumeNotAttachedError) Error() string {
	return fmt.Sprintf(
		"volumeName %q does not exist in the list of attached volumes",
		err.volumeName)
}

func newVolumeNotAttachedError(volumeName v1.UniqueVolumeName) error {
	return volumeNotAttachedError{
		volumeName: volumeName,
	}
}

// Compile-time check to ensure remountRequiredError implements the error interface
var _ error = remountRequiredError{}

// remountRequiredError is an error returned when PodExistsInVolume() found
// volume/pod attached/mounted but remountRequired was true, indicating the
// given volume should be remounted to the pod to reflect changes in the
// referencing pod.
type remountRequiredError struct {
	volumeName v1.UniqueVolumeName
	podName    volumetypes.UniquePodName
}

func (err remountRequiredError) Error() string {
	return fmt.Sprintf(
		"volumeName %q is mounted to %q but should be remounted",
		err.volumeName, err.podName)
}

func newRemountRequiredError(volumeName v1.UniqueVolumeName, podName volumetypes.UniquePodName) error {
	return remountRequiredError{
		volumeName: volumeName,
		podName:    podName,
	}
}

// FsResizeRequiredError 是一个错误,在 PodExistsInVolume() 发现卷/已附加/已挂载但 fsResizeRequired 为 true 时返回,
// 表示在附加/挂载后给定卷接收到了一个调整大小请求.
type FsResizeRequiredError struct {
	CurrentSize resource.Quantity
	volumeName  v1.UniqueVolumeName
	podName     volumetypes.UniquePodName
}

func (err FsResizeRequiredError) Error() string {
	return fmt.Sprintf("volumeName %q mounted to %q needs to resize file system", err.volumeName, err.podName)
}
func newFsResizeRequiredError(volumeName v1.UniqueVolumeName, podName volumetypes.UniquePodName, currentSize resource.Quantity) error {
	return FsResizeRequiredError{
		CurrentSize: currentSize,
		volumeName:  volumeName,
		podName:     podName,
	}
}

func (asw *actualStateOfWorld) newAttachedVolume(attachedVolume *attachedVolume) AttachedVolume {
	seLinuxMountContext := ""
	if utilfeature.DefaultFeatureGate.Enabled(features.SELinuxMountReadWriteOncePod) {
		if attachedVolume.seLinuxMountContext != nil {
			seLinuxMountContext = *attachedVolume.seLinuxMountContext
		}
	}
	return AttachedVolume{
		AttachedVolume: operationexecutor.AttachedVolume{
			VolumeName:          attachedVolume.volumeName,
			VolumeSpec:          attachedVolume.spec,
			NodeName:            asw.nodeName,
			PluginIsAttachable:  attachedVolume.pluginIsAttachable,
			DevicePath:          attachedVolume.devicePath,
			DeviceMountPath:     attachedVolume.deviceMountPath,
			PluginName:          attachedVolume.pluginName,
			SELinuxMountContext: seLinuxMountContext},
		DeviceMountState:    attachedVolume.deviceMountState,
		SELinuxMountContext: seLinuxMountContext,
	}
}

// IsFSResizeRequiredError returns true if the specified error is a
// fsResizeRequiredError.
func IsFSResizeRequiredError(err error) bool {
	_, ok := err.(FsResizeRequiredError)
	return ok
}

// getMountedVolume constructs and returns a MountedVolume object from the given
// mountedPod and attachedVolume objects.
func getMountedVolume(mountedPod *mountedPod, attachedVolume *attachedVolume) MountedVolume {
	seLinuxMountContext := ""
	if attachedVolume.seLinuxMountContext != nil {
		seLinuxMountContext = *attachedVolume.seLinuxMountContext
	}
	return MountedVolume{
		MountedVolume: operationexecutor.MountedVolume{
			PodName:             mountedPod.podName,
			VolumeName:          attachedVolume.volumeName,
			InnerVolumeSpecName: mountedPod.volumeSpec.Name(),
			OuterVolumeSpecName: mountedPod.outerVolumeSpecName,
			PluginName:          attachedVolume.pluginName,
			PodUID:              mountedPod.podUID,
			Mounter:             mountedPod.mounter,
			BlockVolumeMapper:   mountedPod.blockVolumeMapper,
			VolumeGidValue:      mountedPod.volumeGidValue,
			VolumeSpec:          mountedPod.volumeSpec,
			DeviceMountPath:     attachedVolume.deviceMountPath,
			SELinuxMountContext: seLinuxMountContext,
		},
	}
}

// seLinuxMountMismatchError is an error returned when PodExistsInVolume() found
// a volume mounted with a different SELinux label than expected.
type seLinuxMountMismatchError struct {
	volumeName v1.UniqueVolumeName
}

func (err seLinuxMountMismatchError) Error() string {
	return fmt.Sprintf(
		"waiting for unmount of volume %q, because it is already mounted to a different pod with a different SELinux label",
		err.volumeName)
}

func newSELinuxMountMismatchError(volumeName v1.UniqueVolumeName) error {
	return seLinuxMountMismatchError{
		volumeName: volumeName,
	}
}

// IsSELinuxMountMismatchError returns true if the specified error is a
// seLinuxMountMismatchError.
func IsSELinuxMountMismatchError(err error) bool {
	_, ok := err.(seLinuxMountMismatchError)
	return ok
}

// MarkRemountRequired 标记volume 需要重新挂载
func (asw *actualStateOfWorld) MarkRemountRequired(podName volumetypes.UniquePodName) {
	asw.Lock()
	defer asw.Unlock()
	for volumeName, volumeObj := range asw.attachedVolumes {
		if podObj, podExists := volumeObj.mountedPods[podName]; podExists { // 重新挂载的前提,是他已经挂载了
			volumePlugin, err := asw.volumePluginMgr.FindPluginBySpec(podObj.volumeSpec)
			if err != nil || volumePlugin == nil {
				// Log and continue processing
				klog.ErrorS(nil, "MarkRemountRequired failed to FindPluginBySpec for volume", "uniquePodName", podObj.podName, "podUID", podObj.podUID, "volumeName", volumeName, "volumeSpecName", podObj.volumeSpec.Name())
				continue
			}

			if volumePlugin.RequiresRemount(podObj.volumeSpec) {
				podObj.remountRequired = true
				asw.attachedVolumes[volumeName].mountedPods[podName] = podObj
			}
		}
	}
}
func (asw *actualStateOfWorld) PodRemovedFromVolume(podName volumetypes.UniquePodName, volumeName v1.UniqueVolumeName) bool {
	asw.RLock()
	defer asw.RUnlock()

	volumeObj, volumeExists := asw.attachedVolumes[volumeName]
	if !volumeExists {
		return true
	}

	podObj, podExists := volumeObj.mountedPods[podName]
	if podExists {
		// if volume mount was uncertain we should keep trying to unmount the volume
		if podObj.volumeMountStateForPod == operationexecutor.VolumeMountUncertain {
			return false
		}
		if podObj.volumeMountStateForPod == operationexecutor.VolumeMounted {
			return false
		}
	}
	return true
}

// IsVolumeNotAttachedError returns true if the specified error is a volumeNotAttachedError.
func IsVolumeNotAttachedError(err error) bool {
	_, ok := err.(volumeNotAttachedError)
	return ok
}

// IsRemountRequiredError returns true if the specified error is a
// remountRequiredError.
func IsRemountRequiredError(err error) bool {
	_, ok := err.(remountRequiredError)
	return ok
}

func (asw *actualStateOfWorld) GetGloballyMountedVolumes() []AttachedVolume {
	asw.RLock()
	defer asw.RUnlock()
	globallyMountedVolumes := make([]AttachedVolume, 0 /* len */, len(asw.attachedVolumes) /* cap */)
	for _, volumeObj := range asw.attachedVolumes {
		if volumeObj.deviceMountState == operationexecutor.DeviceGloballyMounted {
			globallyMountedVolumes = append(globallyMountedVolumes, asw.newAttachedVolume(&volumeObj))
		}
	}

	return globallyMountedVolumes
}

func (asw *actualStateOfWorld) GetAttachedVolumes() []AttachedVolume {
	asw.RLock()
	defer asw.RUnlock()
	allAttachedVolumes := make([]AttachedVolume, 0 /* len */, len(asw.attachedVolumes) /* cap */)
	for _, volumeObj := range asw.attachedVolumes {
		allAttachedVolumes = append(allAttachedVolumes, asw.newAttachedVolume(&volumeObj))
	}

	return allAttachedVolumes
}

func (asw *actualStateOfWorld) GetUnmountedVolumes() []AttachedVolume {
	asw.RLock()
	defer asw.RUnlock()
	unmountedVolumes := make([]AttachedVolume, 0 /* len */, len(asw.attachedVolumes) /* cap */)
	for _, volumeObj := range asw.attachedVolumes {
		if len(volumeObj.mountedPods) == 0 {
			unmountedVolumes = append(unmountedVolumes, asw.newAttachedVolume(&volumeObj))
		}
	}

	return unmountedVolumes
}

func (asw *actualStateOfWorld) VolumeExistsWithSpecName(podName volumetypes.UniquePodName, volumeSpecName string) bool {
	asw.RLock()
	defer asw.RUnlock()
	for _, volumeObj := range asw.attachedVolumes {
		if podObj, podExists := volumeObj.mountedPods[podName]; podExists {
			if podObj.volumeSpec.Name() == volumeSpecName {
				return true
			}
		}
	}
	return false
}

func (asw *actualStateOfWorld) VolumeExists(volumeName v1.UniqueVolumeName) bool {
	asw.RLock()
	defer asw.RUnlock()
	_, volumeExists := asw.attachedVolumes[volumeName]
	return volumeExists
}

func (asw *actualStateOfWorld) GetMountedVolumes() []MountedVolume {
	asw.RLock()
	defer asw.RUnlock()
	mountedVolume := make([]MountedVolume, 0 /* len */, len(asw.attachedVolumes) /* cap */)
	for _, volumeObj := range asw.attachedVolumes {
		for _, podObj := range volumeObj.mountedPods {
			if podObj.volumeMountStateForPod == operationexecutor.VolumeMounted {
				mountedVolume = append(mountedVolume, getMountedVolume(&podObj, &volumeObj))
			}
		}
	}
	return mountedVolume
}

// GetAllMountedVolumes returns all volumes which could be locally mounted for a pod.
func (asw *actualStateOfWorld) GetAllMountedVolumes() []MountedVolume {
	asw.RLock()
	defer asw.RUnlock()
	mountedVolume := make([]MountedVolume, 0 /* len */, len(asw.attachedVolumes) /* cap */)
	for _, volumeObj := range asw.attachedVolumes {
		for _, podObj := range volumeObj.mountedPods {
			if podObj.volumeMountStateForPod == operationexecutor.VolumeMounted ||
				podObj.volumeMountStateForPod == operationexecutor.VolumeMountUncertain {
				mountedVolume = append(mountedVolume, getMountedVolume(&podObj, &volumeObj))
			}
		}
	}

	return mountedVolume
}

func (asw *actualStateOfWorld) GetMountedVolumesForPod(podName volumetypes.UniquePodName) []MountedVolume {
	asw.RLock()
	defer asw.RUnlock()
	mountedVolume := make([]MountedVolume, 0 /* len */, len(asw.attachedVolumes) /* cap */)
	for _, volumeObj := range asw.attachedVolumes {
		for mountedPodName, podObj := range volumeObj.mountedPods {
			if mountedPodName == podName && podObj.volumeMountStateForPod == operationexecutor.VolumeMounted {
				mountedVolume = append(mountedVolume, getMountedVolume(&podObj, &volumeObj))
			}
		}
	}

	return mountedVolume
}

func (asw *actualStateOfWorld) GetPossiblyMountedVolumesForPod(podName volumetypes.UniquePodName) []MountedVolume {
	asw.RLock()
	defer asw.RUnlock()
	mountedVolume := make([]MountedVolume, 0 /* len */, len(asw.attachedVolumes) /* cap */)
	for _, volumeObj := range asw.attachedVolumes {
		for mountedPodName, podObj := range volumeObj.mountedPods {
			if mountedPodName == podName && (podObj.volumeMountStateForPod == operationexecutor.VolumeMounted || podObj.volumeMountStateForPod == operationexecutor.VolumeMountUncertain) {
				mountedVolume = append(mountedVolume, getMountedVolume(&podObj, &volumeObj))
			}
		}
	}

	return mountedVolume
}

func (asw *actualStateOfWorld) DeletePodFromVolume(podName volumetypes.UniquePodName, volumeName v1.UniqueVolumeName) error {
	asw.Lock()
	defer asw.Unlock()

	volumeObj, volumeExists := asw.attachedVolumes[volumeName]
	if !volumeExists {
		return fmt.Errorf(
			"no volume with the name %q exists in the list of attached volumes",
			volumeName)
	}

	_, podExists := volumeObj.mountedPods[podName]
	if podExists {
		delete(asw.attachedVolumes[volumeName].mountedPods, podName)
	}

	// if there were reconstructed volumes, we should remove them
	_, podExists = asw.foundDuringReconstruction[volumeName]
	if podExists {
		delete(asw.foundDuringReconstruction[volumeName], podName)
	}

	return nil
}

func (asw *actualStateOfWorld) DeleteVolume(volumeName v1.UniqueVolumeName) error {
	asw.Lock()
	defer asw.Unlock()

	volumeObj, volumeExists := asw.attachedVolumes[volumeName]
	if !volumeExists {
		return nil
	}

	if len(volumeObj.mountedPods) != 0 {
		return fmt.Errorf(
			"failed to DeleteVolume %q, it still has %v mountedPods",
			volumeName,
			len(volumeObj.mountedPods))
	}

	delete(asw.attachedVolumes, volumeName)
	delete(asw.foundDuringReconstruction, volumeName)
	return nil
}

// SyncReconstructedVolume 检查 asw 中的 volume.outerVolumeSpecName 字段和从 dsw 中重建的该字段的值是否匹配,如果不匹配,则更新该字段的值为从 dsw 中重建的值.
func (asw *actualStateOfWorld) SyncReconstructedVolume(volumeName v1.UniqueVolumeName, podName volumetypes.UniquePodName, outerVolumeSpecName string) {
	asw.Lock()
	defer asw.Unlock()
	if volumeObj, volumeExists := asw.attachedVolumes[volumeName]; volumeExists {
		if podObj, podExists := volumeObj.mountedPods[podName]; podExists {
			if podObj.outerVolumeSpecName != outerVolumeSpecName {
				podObj.outerVolumeSpecName = outerVolumeSpecName
				asw.attachedVolumes[volumeName].mountedPods[podName] = podObj
			}
		}
	}
}

// UpdateReconstructedDevicePath 根据节点（Node）的状态（Status）中的已挂载卷（VolumesAttached）,更新重构卷的设备路径（devicePath）
// 只有在卷仍然不确定的情况下,才会更新ASW.如果在此期间卷已挂载,则其设备路径必须已通过此类更新进行了修复.
func (asw *actualStateOfWorld) UpdateReconstructedDevicePath(volumeName v1.UniqueVolumeName, devicePath string) {
	asw.Lock()
	defer asw.Unlock()

	volumeObj, volumeExists := asw.attachedVolumes[volumeName]
	if !volumeExists {
		return
	}
	if volumeObj.deviceMountState != operationexecutor.DeviceMountUncertain {
		// Reconciler must have updated volume state, i.e. when a pod uses the volume and
		// succeeded mounting the volume. Such update has fixed the device path.
		return
	}

	volumeObj.devicePath = devicePath
	asw.attachedVolumes[volumeName] = volumeObj
}
func (asw *actualStateOfWorld) GetDeviceMountState(volumeName v1.UniqueVolumeName) operationexecutor.DeviceMountState {
	asw.RLock()
	defer asw.RUnlock()

	volumeObj, volumeExists := asw.attachedVolumes[volumeName]
	if !volumeExists {
		return operationexecutor.DeviceNotMounted
	}

	return volumeObj.deviceMountState
}

func (asw *actualStateOfWorld) MarkForInUseExpansionError(volumeName v1.UniqueVolumeName) {
	asw.Lock()
	defer asw.Unlock()

	volumeObj, ok := asw.attachedVolumes[volumeName]
	if ok {
		volumeObj.volumeInUseErrorForExpansion = true
		asw.attachedVolumes[volumeName] = volumeObj
	}
}

// addVolume adds the given volume to the cache indicating the specified
// volume is attached to this node. If no volume name is supplied, a unique
// volume name is generated from the volumeSpec and returned on success. If a
// volume with the same generated name already exists, this is a noop. If no
// volume plugin can support the given volumeSpec or more than one plugin can
// support it, an error is returned.
func (asw *actualStateOfWorld) addVolume(volumeName v1.UniqueVolumeName, volumeSpec *volume.Spec, devicePath string) error {
	asw.Lock()
	defer asw.Unlock()

	volumePlugin, err := asw.volumePluginMgr.FindPluginBySpec(volumeSpec)
	if err != nil || volumePlugin == nil {
		return fmt.Errorf("failed to get Plugin from volumeSpec for volume %q err=%v", volumeSpec.Name(), err)
	}

	if len(volumeName) == 0 {
		volumeName, err = util.GetUniqueVolumeNameFromSpec(volumePlugin, volumeSpec)
		if err != nil {
			return fmt.Errorf("failed to GetUniqueVolumeNameFromSpec for volumeSpec %q using volume plugin %q err=%v", volumeSpec.Name(), volumePlugin.GetPluginName(), err)
		}
	}

	pluginIsAttachable := false
	if attachablePlugin, err := asw.volumePluginMgr.FindAttachablePluginBySpec(volumeSpec); err == nil && attachablePlugin != nil {
		pluginIsAttachable = true
	}

	volumeObj, volumeExists := asw.attachedVolumes[volumeName]
	if !volumeExists {
		volumeObj = attachedVolume{
			volumeName:         volumeName,
			spec:               volumeSpec,
			mountedPods:        make(map[volumetypes.UniquePodName]mountedPod),
			pluginName:         volumePlugin.GetPluginName(),
			pluginIsAttachable: pluginIsAttachable,
			deviceMountState:   operationexecutor.DeviceNotMounted,
			devicePath:         devicePath,
		}
	} else {
		// If volume object already exists, update the fields such as device path
		volumeObj.devicePath = devicePath
		klog.V(2).InfoS("Volume is already added to attachedVolume list, update device path", "volumeName", volumeName, "path", devicePath)
	}
	asw.attachedVolumes[volumeName] = volumeObj

	return nil
}

func (asw *actualStateOfWorld) AddPodToVolume(markVolumeOpts operationexecutor.MarkVolumeOpts) error {
	podName := markVolumeOpts.PodName
	podUID := markVolumeOpts.PodUID
	volumeName := markVolumeOpts.VolumeName
	mounter := markVolumeOpts.Mounter
	blockVolumeMapper := markVolumeOpts.BlockVolumeMapper
	outerVolumeSpecName := markVolumeOpts.OuterVolumeSpecName
	volumeGidValue := markVolumeOpts.VolumeGidVolume
	volumeSpec := markVolumeOpts.VolumeSpec
	asw.Lock()
	defer asw.Unlock()

	volumeObj, volumeExists := asw.attachedVolumes[volumeName]
	if !volumeExists {
		return fmt.Errorf("no volume with the name %q exists in the list of attached volumes", volumeName)
	}

	podObj, podExists := volumeObj.mountedPods[podName]

	updateUncertainVolume := false
	if podExists {
		// Update uncertain volumes - the new markVolumeOpts may have updated information.
		// Especially reconstructed volumes (marked as uncertain during reconstruction) need
		// an update.
		updateUncertainVolume = utilfeature.DefaultFeatureGate.Enabled(features.SELinuxMountReadWriteOncePod) && podObj.volumeMountStateForPod == operationexecutor.VolumeMountUncertain
	}
	if !podExists || updateUncertainVolume {
		// Add new mountedPod or update existing one.
		podObj = mountedPod{
			podName:                podName,
			podUID:                 podUID,
			mounter:                mounter,
			blockVolumeMapper:      blockVolumeMapper,
			outerVolumeSpecName:    outerVolumeSpecName,
			volumeGidValue:         volumeGidValue,
			volumeSpec:             volumeSpec,
			volumeMountStateForPod: markVolumeOpts.VolumeMountState,
			seLinuxMountContext:    markVolumeOpts.SELinuxMountContext,
		}
	}

	// If pod exists, reset remountRequired value
	podObj.remountRequired = false
	podObj.volumeMountStateForPod = markVolumeOpts.VolumeMountState

	// if volume is mounted successfully, then it should be removed from foundDuringReconstruction map
	if markVolumeOpts.VolumeMountState == operationexecutor.VolumeMounted {
		delete(asw.foundDuringReconstruction[volumeName], podName)
	}
	if mounter != nil {
		// The mounter stored in the object may have old information,
		// use the newest one.
		podObj.mounter = mounter
	}
	asw.attachedVolumes[volumeName].mountedPods[podName] = podObj
	if utilfeature.DefaultFeatureGate.Enabled(features.SELinuxMountReadWriteOncePod) {
		// Store the mount context also in the AttachedVolume to have a global volume context
		// for a quick comparison in PodExistsInVolume.
		if volumeObj.seLinuxMountContext == nil {
			volumeObj.seLinuxMountContext = &markVolumeOpts.SELinuxMountContext
			asw.attachedVolumes[volumeName] = volumeObj
		}
	}

	return nil
}
func (asw *actualStateOfWorld) MarkVolumeAsAttached(volumeName v1.UniqueVolumeName, volumeSpec *volume.Spec, _ types.NodeName, devicePath string) error {
	return asw.addVolume(volumeName, volumeSpec, devicePath)
}

func (asw *actualStateOfWorld) MarkVolumeAsUncertain(volumeName v1.UniqueVolumeName, volumeSpec *volume.Spec, _ types.NodeName) error {
	return nil
}

func (asw *actualStateOfWorld) MarkVolumeAsDetached(volumeName v1.UniqueVolumeName, nodeName types.NodeName) {
	asw.DeleteVolume(volumeName)
}

// IsVolumeReconstructed 判断当前被添加到实际世界状态中的卷是否是在重建过程中发现的.如果是在重建过程中发现的,则返回true.
func (asw *actualStateOfWorld) IsVolumeReconstructed(volumeName v1.UniqueVolumeName, podName volumetypes.UniquePodName) bool {
	volumeState := asw.GetVolumeMountState(volumeName, podName)

	// only uncertain volumes are reconstructed
	if volumeState != operationexecutor.VolumeMountUncertain {
		return false
	}

	asw.RLock()
	defer asw.RUnlock()
	podMap, ok := asw.foundDuringReconstruction[volumeName]
	if !ok {
		return false
	}
	_, foundPod := podMap[podName]
	return foundPod
}

func (asw *actualStateOfWorld) MarkVolumeAsMounted(markVolumeOpts operationexecutor.MarkVolumeOpts) error {
	return asw.AddPodToVolume(markVolumeOpts)
}

func (asw *actualStateOfWorld) AddVolumeToReportAsAttached(volumeName v1.UniqueVolumeName, nodeName types.NodeName) {
	// no operation for kubelet side
}

func (asw *actualStateOfWorld) RemoveVolumeFromReportAsAttached(volumeName v1.UniqueVolumeName, nodeName types.NodeName) error {
	// no operation for kubelet side
	return nil
}

func (asw *actualStateOfWorld) MarkVolumeAsUnmounted(podName volumetypes.UniquePodName, volumeName v1.UniqueVolumeName) error {
	return asw.DeletePodFromVolume(podName, volumeName)
}

func (asw *actualStateOfWorld) MarkDeviceAsMounted(volumeName v1.UniqueVolumeName, devicePath, deviceMountPath, seLinuxMountContext string) error {
	return asw.SetDeviceMountState(volumeName, operationexecutor.DeviceGloballyMounted, devicePath, deviceMountPath, seLinuxMountContext)
}

func (asw *actualStateOfWorld) MarkDeviceAsUncertain(volumeName v1.UniqueVolumeName, devicePath, deviceMountPath, seLinuxMountContext string) error {
	return asw.SetDeviceMountState(volumeName, operationexecutor.DeviceMountUncertain, devicePath, deviceMountPath, seLinuxMountContext)
}

func (asw *actualStateOfWorld) MarkVolumeMountAsUncertain(markVolumeOpts operationexecutor.MarkVolumeOpts) error {
	markVolumeOpts.VolumeMountState = operationexecutor.VolumeMountUncertain
	return asw.AddPodToVolume(markVolumeOpts)
}

func (asw *actualStateOfWorld) MarkDeviceAsUnmounted(volumeName v1.UniqueVolumeName) error {
	return asw.SetDeviceMountState(volumeName, operationexecutor.DeviceNotMounted, "", "", "")
}
