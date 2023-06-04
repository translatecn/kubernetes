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

// Package operationexecutor implements interfaces that enable execution of
// attach, detach, mount, and unmount operations with a
// nestedpendingoperations so that more than one operation is never triggered
// on the same volume for the same pod.
package operationexecutor

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"

	"k8s.io/klog/v2"
	"k8s.io/mount-utils"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/kubernetes/pkg/volume"
	"k8s.io/kubernetes/pkg/volume/util"
	"k8s.io/kubernetes/pkg/volume/util/hostutil"
	"k8s.io/kubernetes/pkg/volume/util/nestedpendingoperations"
	volumetypes "k8s.io/kubernetes/pkg/volume/util/types"
	"k8s.io/kubernetes/pkg/volume/util/volumepathhandler"
)

type OperationExecutor interface {
	AttachVolume(volumeToAttach VolumeToAttach, actualStateOfWorld ActualStateOfWorldAttacherUpdater) error // 将卷附加到volumeToAttach中指定的节点.然后它更新了世界的实际状态以反映这一点.
	// VerifyVolumesAreAttachedPerNode verifies the given list of volumes to see whether they are still attached to the node.
	// If any volume is not attached right now, it will update the actual state of the world to reflect that.
	// Note that this operation could be operated concurrently with other attach/detach operations.
	// In theory (but very unlikely in practise), race condition among these operations might mark volume as detached
	// even if it is attached. But reconciler can correct this in a short period of time.
	VerifyVolumesAreAttachedPerNode(AttachedVolumes []AttachedVolume, nodeName types.NodeName, actualStateOfWorld ActualStateOfWorldAttacherUpdater) error

	// VerifyVolumesAreAttached verifies volumes being used in entire cluster and if they are still attached to the node
	// If any volume is not attached right now, it will update actual state of world to reflect that.
	VerifyVolumesAreAttached(volumesToVerify map[types.NodeName][]AttachedVolume, actualStateOfWorld ActualStateOfWorldAttacherUpdater)

	// DetachVolume detaches the volume from the node specified in
	// volumeToDetach, and updates the actual state of the world to reflect
	// that. If verifySafeToDetach is set, a call is made to the fetch the node
	// object and it is used to verify that the volume does not exist in Node's
	// Status.VolumesInUse list (operation fails with error if it is).
	DetachVolume(volumeToDetach AttachedVolume, verifySafeToDetach bool, actualStateOfWorld ActualStateOfWorldAttacherUpdater) error

	// MountVolume 这段代码的意思是：如果一个卷的volumeMode是'Filesystem',MountVolume会将该卷挂载到volumeToMount中指定的Pod中.
	// * 等待设备完成附加（仅适用于可附加的卷）.
	// * 将设备挂载到全局挂载路径（仅适用于可附加的卷）.
	// * 更新实际世界状态以反映卷已全局挂载（仅适用于可附加的卷）.
	// * 将卷挂载到Pod特定路径.
	// * 更新实际世界状态以反映卷已挂载到Pod路径中.
	//
	// 参数"isRemount"是信息性的,用于调整日志记录的详细程度.例如,初始挂载比重新挂载更值得记录日志.
	//
	// 对于'Block' volumeMode,此方法从volumeToMount中指定的Pod和全局映射路径创建符号链接到卷.
	// * 等待设备完成附加（仅适用于可附加的卷）.
	// * 更新实际世界状态以反映卷已全局挂载/映射.
	// * 使用符号链接将卷映射到全局映射路径.
	// * 使用符号链接将卷映射到Pod设备映射路径.
	// * 更新实际世界状态以反映卷已映射/挂载到Pod路径中.
	MountVolume(waitForAttachTimeout time.Duration, volumeToMount VolumeToMount, actualStateOfWorld ActualStateOfWorldMounterUpdater, isRemount bool) error

	// UnmountVolume
	// 'Filesystem' volumeMode,UnmountVolume方法会从volumeToUnmount中指定的pod中卸载该卷,并更新实际状态以反映此操作.
	//      'Block' volumeMode,此方法将从volumeToUnmount中指定的pod设备映射路径和全局映射路径中取消卷的符号链接.然后,更新实际状态以反映此操作.
	UnmountVolume(volumeToUnmount MountedVolume, actualStateOfWorld ActualStateOfWorldMounterUpdater, podsDir string) error

	// If a volume has 'Filesystem' volumeMode, UnmountDevice unmounts the
	// volumes global mount path from the device (for attachable volumes only,
	// freeing it for detach. It then updates the actual state of the world to
	// reflect that.
	//
	// For 'Block' volumeMode, this method checks number of symbolic links under
	// global map path. If number of reference is zero, remove global map path
	// directory and free a volume for detach.
	// It then updates the actual state of the world to reflect that.
	UnmountDevice(deviceToDetach AttachedVolume, actualStateOfWorld ActualStateOfWorldMounterUpdater, hostutil hostutil.HostUtils) error
	// VerifyControllerAttachedVolume 检查指定的卷是否存在于指定节点的 AttachedVolumes 状态字段中.它使用 kubeClient 来获取节点对象.
	// 如果找到了该卷,则会更新实际世界的状态以标记该卷已附加.
	// 如果该卷没有实现 attacher 接口,则假定该卷已附加,并相应地更新实际世界的状态.
	// 如果未找到该卷或存在错误（例如获取节点对象时）,则返回错误,触发指数级退避重试.
	VerifyControllerAttachedVolume(volumeToMount VolumeToMount, nodeName types.NodeName, actualStateOfWorld ActualStateOfWorldAttacherUpdater) error

	// IsOperationPending returns true if an operation for the given volumeName
	// and one of podName or nodeName is pending, otherwise it returns false
	IsOperationPending(volumeName v1.UniqueVolumeName, podName volumetypes.UniquePodName, nodeName types.NodeName) bool
	// IsOperationSafeToRetry returns false if an operation for the given volumeName
	// and one of podName or nodeName is pending or in exponential backoff, otherwise it returns true
	IsOperationSafeToRetry(volumeName v1.UniqueVolumeName, podName volumetypes.UniquePodName, nodeName types.NodeName, operationName string) bool

	ExpandInUseVolume(volumeToMount VolumeToMount, actualStateOfWorld ActualStateOfWorldMounterUpdater, currentSize resource.Quantity) error
	// ReconstructVolumeOperation construct a new volumeSpec and returns it created by plugin
	ReconstructVolumeOperation(volumeMode v1.PersistentVolumeMode, plugin volume.VolumePlugin, mapperPlugin volume.BlockVolumePlugin, uid types.UID, podName volumetypes.UniquePodName, volumeSpecName string, volumePath string, pluginName string) (volume.ReconstructedVolume, error)
	// CheckVolumeExistenceOperation checks volume existence
	CheckVolumeExistenceOperation(volumeSpec *volume.Spec, mountPath, volumeName string, mounter mount.Interface, uniqueVolumeName v1.UniqueVolumeName, podName volumetypes.UniquePodName, podUID types.UID, attachable volume.AttachableVolumePlugin) (bool, error)
}

// NewOperationExecutor returns a new instance of OperationExecutor.
func NewOperationExecutor(
	operationGenerator OperationGenerator) OperationExecutor {

	return &operationExecutor{
		pendingOperations: nestedpendingoperations.NewNestedPendingOperations(
			true /* exponentialBackOffOnError */),
		operationGenerator: operationGenerator,
	}
}

// MarkVolumeOpts is a struct to pass arguments to MountVolume functions
type MarkVolumeOpts struct {
	PodName             volumetypes.UniquePodName
	PodUID              types.UID
	VolumeName          v1.UniqueVolumeName
	Mounter             volume.Mounter
	BlockVolumeMapper   volume.BlockVolumeMapper
	OuterVolumeSpecName string
	VolumeGidVolume     string
	VolumeSpec          *volume.Spec
	VolumeMountState    VolumeMountState
	SELinuxMountContext string
}

// ActualStateOfWorldMounterUpdater defines a set of operations updating the actual
// state of the world cache after successful mount/unmount.
type ActualStateOfWorldMounterUpdater interface {
	MarkVolumeAsMounted(markVolumeOpts MarkVolumeOpts) error
	MarkVolumeAsUnmounted(podName volumetypes.UniquePodName, volumeName v1.UniqueVolumeName) error

	// MarkVolumeMountAsUncertain marks state of volume mount for the pod uncertain
	MarkVolumeMountAsUncertain(markVolumeOpts MarkVolumeOpts) error

	MarkDeviceAsMounted(volumeName v1.UniqueVolumeName, devicePath, deviceMountPath, seLinuxMountContext string) error

	// MarkDeviceAsUncertain marks device state in global mount path as uncertain
	MarkDeviceAsUncertain(volumeName v1.UniqueVolumeName, devicePath, deviceMountPath, seLinuxMountContext string) error

	// Marks the specified volume as having its global mount unmounted.
	MarkDeviceAsUnmounted(volumeName v1.UniqueVolumeName) error
	// MarkVolumeAsResized 标记指定卷的文件系统调整大小请求已完成.
	MarkVolumeAsResized(volumeName v1.UniqueVolumeName, claimSize *resource.Quantity) bool
	GetDeviceMountState(volumeName v1.UniqueVolumeName) DeviceMountState // 返回挂载状态

	// GetVolumeMountState returns mount state of the volume for the Pod
	GetVolumeMountState(volumName v1.UniqueVolumeName, podName volumetypes.UniquePodName) VolumeMountState

	// IsVolumeMountedElsewhere 判断指定的卷是否已经被其他Pod挂载,而不是当前指定的Pod.它将返回一个布尔值,表示指定的卷是否已经在其他Pod中挂载.
	// 在容器编排系统中,可能会有多个Pod使用同一卷进行共享存储.当需要对卷进行操作时,需要确保卷未被其他Pod挂载,以免造成数据损坏或冲突.
	// 因此,该函数可以用于检查卷是否已经在其他Pod中使用,以便在需要时采取适当的措施.
	IsVolumeMountedElsewhere(volumeName v1.UniqueVolumeName, podName volumetypes.UniquePodName) bool

	// MarkForInUseExpansionError marks the volume to have in-use error during expansion.
	// volume expansion must not be retried for this volume
	MarkForInUseExpansionError(volumeName v1.UniqueVolumeName)
	// CheckAndMarkVolumeAsUncertainViaReconstruction 检查并将卷标记为不确定状态.如果该卷已经存在于实际世界状态中,则不会将其添加到实际世界状态中,以避免覆盖先前存储的任何状态.
	//如果将卷添加到实际世界状态中,则返回true,否则返回false.如果将卷添加到实际世界状态中时出现错误,则返回错误.
	CheckAndMarkVolumeAsUncertainViaReconstruction(opts MarkVolumeOpts) (bool, error)

	// CheckAndMarkDeviceUncertainViaReconstruction 仅在设备不在实际世界状态中时才将其添加到该状态中.这样可以避免覆盖之前存储的任何状态.
	// 函数只提供设备挂载路径（deviceMountPath）,因为设备路径（devicePath）已经在VerifyControllerAttachedVolume函数中确定
	CheckAndMarkDeviceUncertainViaReconstruction(volumeName v1.UniqueVolumeName, deviceMountPath string) bool
	// IsVolumeReconstructed 判断当前被添加到实际世界状态中的卷是否是在重建过程中发现的.如果是在重建过程中发现的,则返回true.
	IsVolumeReconstructed(volumeName v1.UniqueVolumeName, podName volumetypes.UniquePodName) bool
}

// ActualStateOfWorldAttacherUpdater defines a set of operations updating the
// actual state of the world cache after successful attach/detach/mount/unmount.
type ActualStateOfWorldAttacherUpdater interface {
	// Marks the specified volume as attached to the specified node.  If the
	// volume name is supplied, that volume name will be used.  If not, the
	// volume name is computed using the result from querying the plugin.
	//
	// TODO: in the future, we should be able to remove the volumeName
	// argument to this method -- since it is used only for attachable
	// volumes.  See issue 29695.
	MarkVolumeAsAttached(volumeName v1.UniqueVolumeName, volumeSpec *volume.Spec, nodeName types.NodeName, devicePath string) error

	// Marks the specified volume as *possibly* attached to the specified node.
	// If an attach operation fails, the attach/detach controller does not know for certain if the volume is attached or not.
	// If the volume name is supplied, that volume name will be used.  If not, the
	// volume name is computed using the result from querying the plugin.
	MarkVolumeAsUncertain(volumeName v1.UniqueVolumeName, volumeSpec *volume.Spec, nodeName types.NodeName) error

	// Marks the specified volume as detached from the specified node
	MarkVolumeAsDetached(volumeName v1.UniqueVolumeName, nodeName types.NodeName)

	// Marks desire to detach the specified volume (remove the volume from the node's
	// volumesToReportAsAttached list)
	RemoveVolumeFromReportAsAttached(volumeName v1.UniqueVolumeName, nodeName types.NodeName) error

	// Unmarks the desire to detach for the specified volume (add the volume back to
	// the node's volumesToReportAsAttached list)
	AddVolumeToReportAsAttached(volumeName v1.UniqueVolumeName, nodeName types.NodeName)

	// InitializeClaimSize 通过读取pvc.Status.Capacity来设置pvc 大小.
	InitializeClaimSize(volumeName v1.UniqueVolumeName, claimSize *resource.Quantity)

	GetClaimSize(volumeName v1.UniqueVolumeName) *resource.Quantity
}

// VolumeLogger defines a set of operations for generating volume-related logging and error msgs
type VolumeLogger interface {
	// Creates a detailed msg that can be used in logs
	// The msg format follows the pattern "<prefixMsg> <volume details> <suffixMsg>",
	// where each implementation provides the volume details
	GenerateMsgDetailed(prefixMsg, suffixMsg string) (detailedMsg string)

	// Creates a detailed error that can be used in logs.
	// The msg format follows the pattern "<prefixMsg> <volume details>: <err> ",
	GenerateErrorDetailed(prefixMsg string, err error) (detailedErr error)

	// Creates a simple msg that is user friendly and a detailed msg that can be used in logs
	// The msg format follows the pattern "<prefixMsg> <volume details> <suffixMsg>",
	// where each implementation provides the volume details
	GenerateMsg(prefixMsg, suffixMsg string) (simpleMsg, detailedMsg string)

	// Creates a simple error that is user friendly and a detailed error that can be used in logs.
	// The msg format follows the pattern "<prefixMsg> <volume details>: <err> ",
	GenerateError(prefixMsg string, err error) (simpleErr, detailedErr error)
}

// Generates an error string with the format ": <err>" if err exists
func errSuffix(err error) string {
	errStr := ""
	if err != nil {
		errStr = fmt.Sprintf(": %v", err)
	}
	return errStr
}

// Generate a detailed error msg for logs
func generateVolumeMsgDetailed(prefixMsg, suffixMsg, volumeName, details string) (detailedMsg string) {
	return fmt.Sprintf("%v for volume %q %v %v", prefixMsg, volumeName, details, suffixMsg)
}

// Generate a simplified error msg for events and a detailed error msg for logs
func generateVolumeMsg(prefixMsg, suffixMsg, volumeName, details string) (simpleMsg, detailedMsg string) {
	simpleMsg = fmt.Sprintf("%v for volume %q %v", prefixMsg, volumeName, suffixMsg)
	return simpleMsg, generateVolumeMsgDetailed(prefixMsg, suffixMsg, volumeName, details)
}

// VolumeToAttach represents a volume that should be attached to a node.
type VolumeToAttach struct {
	// MultiAttachErrorReported indicates whether the multi-attach error has been reported for the given volume.
	// It is used to prevent reporting the error from being reported more than once for a given volume.
	MultiAttachErrorReported bool

	// VolumeName is the unique identifier for the volume that should be
	// attached.
	VolumeName v1.UniqueVolumeName

	// VolumeSpec is a volume spec containing the specification for the volume
	// that should be attached.
	VolumeSpec *volume.Spec

	// NodeName is the identifier for the node that the volume should be
	// attached to.
	NodeName types.NodeName
	//这个映射记录了哪些 Pod 使用了该卷,并在哪些节点上运行,以便在对该卷执行操作时可以考虑这些因素
	//例如,如果要卸载该卷,则需要先检查是否有 Pod 在使用该卷,如果有,则需要先将这些 Pod 调度到其他节点上,然后才能卸载该卷.
	//scheduledPods 映射提供了一种方便的方式来跟踪使用该卷的 Pod,并在必要时对它们进行操作.
	ScheduledPods []*v1.Pod
}

// GenerateMsgDetailed returns detailed msgs for volumes to attach
func (volume *VolumeToAttach) GenerateMsgDetailed(prefixMsg, suffixMsg string) (detailedMsg string) {
	detailedStr := fmt.Sprintf("(UniqueName: %q) from node %q", volume.VolumeName, volume.NodeName)
	volumeSpecName := "nil"
	if volume.VolumeSpec != nil {
		volumeSpecName = volume.VolumeSpec.Name()
	}
	return generateVolumeMsgDetailed(prefixMsg, suffixMsg, volumeSpecName, detailedStr)
}

// GenerateMsg returns simple and detailed msgs for volumes to attach
func (volume *VolumeToAttach) GenerateMsg(prefixMsg, suffixMsg string) (simpleMsg, detailedMsg string) {
	detailedStr := fmt.Sprintf("(UniqueName: %q) from node %q", volume.VolumeName, volume.NodeName)
	volumeSpecName := "nil"
	if volume.VolumeSpec != nil {
		volumeSpecName = volume.VolumeSpec.Name()
	}
	return generateVolumeMsg(prefixMsg, suffixMsg, volumeSpecName, detailedStr)
}

// GenerateErrorDetailed returns detailed errors for volumes to attach
func (volume *VolumeToAttach) GenerateErrorDetailed(prefixMsg string, err error) (detailedErr error) {
	return fmt.Errorf(volume.GenerateMsgDetailed(prefixMsg, errSuffix(err)))
}

// GenerateError returns simple and detailed errors for volumes to attach
func (volume *VolumeToAttach) GenerateError(prefixMsg string, err error) (simpleErr, detailedErr error) {
	simpleMsg, detailedMsg := volume.GenerateMsg(prefixMsg, errSuffix(err))
	return fmt.Errorf(simpleMsg), fmt.Errorf(detailedMsg)
}

// String combines key fields of the volume for logging in text format.
func (volume *VolumeToAttach) String() string {
	volumeSpecName := "nil"
	if volume.VolumeSpec != nil {
		volumeSpecName = volume.VolumeSpec.Name()
	}
	return fmt.Sprintf("%s (UniqueName: %s) from node %s", volumeSpecName, volume.VolumeName, volume.NodeName)
}

// MarshalLog combines key fields of the volume for logging in a structured format.
func (volume *VolumeToAttach) MarshalLog() interface{} {
	volumeSpecName := "nil"
	if volume.VolumeSpec != nil {
		volumeSpecName = volume.VolumeSpec.Name()
	}
	return struct {
		VolumeName, UniqueName, NodeName string
	}{
		VolumeName: volumeSpecName,
		UniqueName: string(volume.VolumeName),
		NodeName:   string(volume.NodeName),
	}
}

// VolumeToMount 应该附加到此节点并挂载到PodName的卷
type VolumeToMount struct {
	VolumeName              v1.UniqueVolumeName       // 应该挂载的卷的唯一标识符.
	PodName                 volumetypes.UniquePodName // 卷附加后应该挂载到的Pod的唯一标识符.
	VolumeSpec              *volume.Spec              // 包含应该挂载的卷的规格的卷规格
	OuterVolumeSpecName     string                    // 是卷的podSpec.Volume[x].Name.
	Pod                     *v1.Pod                   //
	PluginIsAttachable      bool                      // 此卷的插件 是否实现volume.Attacher接口.
	PluginIsDeviceMountable bool                      // 此卷的插件 是否实现volume.DeviceMounter接口.
	VolumeGidValue          string                    // 包含GID注释的值（如果存在）.
	DevicePath              string                    // 包含卷附加到的节点上的路径.对于不可附加的卷,这为空.
	ReportedInUse           bool                      // 表示该卷已成功添加到节点状态中的VolumesInUse字段中.
	DesiredSizeLimit        *resource.Quantity        // 表示卷大小的期望上限（如果实现了）.
	MountRequestTime        time.Time                 // 表示请求挂载卷的时间.
	PersistentVolumeSize    resource.Quantity         // 存储卷的期望大小.通常,这是pv.Spec.Capacity的大小.
	SELinuxLabel            string                    // 应该用于挂载的SELinux标签.
}

// DeviceMountState 全局路径中的设备挂载状态.
type DeviceMountState string

const (
	DeviceGloballyMounted DeviceMountState = "DeviceGloballyMounted" // 表示设备已成功全局挂载.
	DeviceMountUncertain  DeviceMountState = "DeviceMountUncertain"  // 表示设备可能未被挂载,但是可能正在进行挂载操作,这可能会导致设备挂载成功.
	DeviceNotMounted      DeviceMountState = "DeviceNotMounted"      // 表示设备未在全局挂载.
)

// VolumeMountState Pod本地路径中的卷挂载状态.
type VolumeMountState string

const (
	VolumeMounted        VolumeMountState = "VolumeMounted"        // 表示卷已在Pod的本地路径中挂载.
	VolumeMountUncertain VolumeMountState = "VolumeMountUncertain" // 表示卷可能已经挂载或未挂载在Pod的本地路径中.
	VolumeNotMounted     VolumeMountState = "VolumeNotMounted"     // 表示卷未在Pod的本地路径中挂载.
)

type MountPreConditionFailed struct {
	msg string
}

func (err *MountPreConditionFailed) Error() string {
	return err.msg
}

func NewMountPreConditionFailedError(msg string) *MountPreConditionFailed {
	return &MountPreConditionFailed{msg: msg}
}

func IsMountFailedPreconditionError(err error) bool {
	var failedPreconditionError *MountPreConditionFailed
	return errors.As(err, &failedPreconditionError)
}

// GenerateMsgDetailed returns detailed msgs for volumes to mount
func (volume *VolumeToMount) GenerateMsgDetailed(prefixMsg, suffixMsg string) (detailedMsg string) {
	detailedStr := fmt.Sprintf("(UniqueName: %q) pod %q (UID: %q)", volume.VolumeName, volume.Pod.Name, volume.Pod.UID)
	volumeSpecName := "nil"
	if volume.VolumeSpec != nil {
		volumeSpecName = volume.VolumeSpec.Name()
	}
	return generateVolumeMsgDetailed(prefixMsg, suffixMsg, volumeSpecName, detailedStr)
}

// GenerateMsg returns simple and detailed msgs for volumes to mount
func (volume *VolumeToMount) GenerateMsg(prefixMsg, suffixMsg string) (simpleMsg, detailedMsg string) {
	detailedStr := fmt.Sprintf("(UniqueName: %q) pod %q (UID: %q)", volume.VolumeName, volume.Pod.Name, volume.Pod.UID)
	volumeSpecName := "nil"
	if volume.VolumeSpec != nil {
		volumeSpecName = volume.VolumeSpec.Name()
	}
	return generateVolumeMsg(prefixMsg, suffixMsg, volumeSpecName, detailedStr)
}

// GenerateErrorDetailed returns detailed errors for volumes to mount
func (volume *VolumeToMount) GenerateErrorDetailed(prefixMsg string, err error) (detailedErr error) {
	return fmt.Errorf(volume.GenerateMsgDetailed(prefixMsg, errSuffix(err)))
}

// GenerateError returns simple and detailed errors for volumes to mount
func (volume *VolumeToMount) GenerateError(prefixMsg string, err error) (simpleErr, detailedErr error) {
	simpleMsg, detailedMsg := volume.GenerateMsg(prefixMsg, errSuffix(err))
	return fmt.Errorf(simpleMsg), fmt.Errorf(detailedMsg)
}

// AttachedVolume represents a volume that is attached to a node.
type AttachedVolume struct {
	// VolumeName is the unique identifier for the volume that is attached.
	VolumeName v1.UniqueVolumeName

	// VolumeSpec is the volume spec containing the specification for the
	// volume that is attached.
	VolumeSpec *volume.Spec

	// NodeName is the identifier for the node that the volume is attached to.
	NodeName types.NodeName

	// PluginIsAttachable indicates that the plugin for this volume implements
	// the volume.Attacher interface
	PluginIsAttachable bool

	// DevicePath contains the path on the node where the volume is attached.
	// For non-attachable volumes this is empty.
	DevicePath string

	// DeviceMountPath contains the path on the node where the device should
	// be mounted after it is attached.
	DeviceMountPath string

	// PluginName is the Unescaped Qualified name of the volume plugin used to
	// attach and mount this volume.
	PluginName string

	SELinuxMountContext string
}

// GenerateMsgDetailed returns detailed msgs for attached volumes
func (volume *AttachedVolume) GenerateMsgDetailed(prefixMsg, suffixMsg string) (detailedMsg string) {
	detailedStr := fmt.Sprintf("(UniqueName: %q) on node %q", volume.VolumeName, volume.NodeName)
	volumeSpecName := "nil"
	if volume.VolumeSpec != nil {
		volumeSpecName = volume.VolumeSpec.Name()
	}
	return generateVolumeMsgDetailed(prefixMsg, suffixMsg, volumeSpecName, detailedStr)
}

// GenerateMsg returns simple and detailed msgs for attached volumes
func (volume *AttachedVolume) GenerateMsg(prefixMsg, suffixMsg string) (simpleMsg, detailedMsg string) {
	detailedStr := fmt.Sprintf("(UniqueName: %q) on node %q", volume.VolumeName, volume.NodeName)
	volumeSpecName := "nil"
	if volume.VolumeSpec != nil {
		volumeSpecName = volume.VolumeSpec.Name()
	}
	return generateVolumeMsg(prefixMsg, suffixMsg, volumeSpecName, detailedStr)
}

// GenerateErrorDetailed returns detailed errors for attached volumes
func (volume *AttachedVolume) GenerateErrorDetailed(prefixMsg string, err error) (detailedErr error) {
	return fmt.Errorf(volume.GenerateMsgDetailed(prefixMsg, errSuffix(err)))
}

// GenerateError returns simple and detailed errors for attached volumes
func (volume *AttachedVolume) GenerateError(prefixMsg string, err error) (simpleErr, detailedErr error) {
	simpleMsg, detailedMsg := volume.GenerateMsg(prefixMsg, errSuffix(err))
	return fmt.Errorf(simpleMsg), fmt.Errorf(detailedMsg)
}

// String combines key fields of the volume for logging in text format.
func (volume *AttachedVolume) String() string {
	volumeSpecName := "nil"
	if volume.VolumeSpec != nil {
		volumeSpecName = volume.VolumeSpec.Name()
	}
	return fmt.Sprintf("%s (UniqueName: %s) from node %s", volumeSpecName, volume.VolumeName, volume.NodeName)
}

// MarshalLog combines key fields of the volume for logging in a structured format.
func (volume *AttachedVolume) MarshalLog() interface{} {
	volumeSpecName := "nil"
	if volume.VolumeSpec != nil {
		volumeSpecName = volume.VolumeSpec.Name()
	}
	return struct {
		VolumeName, UniqueName, NodeName string
	}{
		VolumeName: volumeSpecName,
		UniqueName: string(volume.VolumeName),
		NodeName:   string(volume.NodeName),
	}
}

var _ fmt.Stringer = &AttachedVolume{}
var _ logr.Marshaler = &AttachedVolume{}

type MountedVolume struct {
	PodName             volumetypes.UniquePodName
	VolumeName          v1.UniqueVolumeName
	InnerVolumeSpecName string    // /var/lib/kubelet/pods/{podUID}/volumes/{escapeQualifiedPluginName}/{innerVolumeSpecName}/
	OuterVolumeSpecName string    //
	PluginName          string    // /var/lib/kubelet/pods/{podUID}/volumes/{escapeQualifiedPluginName}/{outerVolumeSpecName}/
	PodUID              types.UID // /var/lib/kubelet/pods/{podUID}/volumes/{escapeQualifiedPluginName}/{outerVolumeSpecName}/
	Mounter             volume.Mounter
	BlockVolumeMapper   volume.BlockVolumeMapper
	VolumeGidValue      string
	VolumeSpec          *volume.Spec
	DeviceMountPath     string
	SELinuxMountContext string
}

// GenerateMsgDetailed returns detailed msgs for mounted volumes
func (volume *MountedVolume) GenerateMsgDetailed(prefixMsg, suffixMsg string) (detailedMsg string) {
	detailedStr := fmt.Sprintf("(UniqueName: %q) pod %q (UID: %q)", volume.VolumeName, volume.PodName, volume.PodUID)
	return generateVolumeMsgDetailed(prefixMsg, suffixMsg, volume.OuterVolumeSpecName, detailedStr)
}

// GenerateMsg returns simple and detailed msgs for mounted volumes
func (volume *MountedVolume) GenerateMsg(prefixMsg, suffixMsg string) (simpleMsg, detailedMsg string) {
	detailedStr := fmt.Sprintf("(UniqueName: %q) pod %q (UID: %q)", volume.VolumeName, volume.PodName, volume.PodUID)
	return generateVolumeMsg(prefixMsg, suffixMsg, volume.OuterVolumeSpecName, detailedStr)
}

// GenerateErrorDetailed returns simple and detailed errors for mounted volumes
func (volume *MountedVolume) GenerateErrorDetailed(prefixMsg string, err error) (detailedErr error) {
	return fmt.Errorf(volume.GenerateMsgDetailed(prefixMsg, errSuffix(err)))
}

// GenerateError returns simple and detailed errors for mounted volumes
func (volume *MountedVolume) GenerateError(prefixMsg string, err error) (simpleErr, detailedErr error) {
	simpleMsg, detailedMsg := volume.GenerateMsg(prefixMsg, errSuffix(err))
	return fmt.Errorf(simpleMsg), fmt.Errorf(detailedMsg)
}

type operationExecutor struct {
	// pendingOperations 用于跟踪挂起的attach和detach操作,以避免在同一个卷上启动多个操作.
	pendingOperations nestedpendingoperations.NestedPendingOperations
	// operationGenerator 提供生成卷函数的实现.
	operationGenerator OperationGenerator
}

func (oe *operationExecutor) IsOperationPending(volumeName v1.UniqueVolumeName, podName volumetypes.UniquePodName, nodeName types.NodeName) bool {
	return oe.pendingOperations.IsOperationPending(volumeName, podName, nodeName)
}

func (oe *operationExecutor) IsOperationSafeToRetry(volumeName v1.UniqueVolumeName, podName volumetypes.UniquePodName, nodeName types.NodeName, operationName string) bool {
	return oe.pendingOperations.IsOperationSafeToRetry(volumeName, podName, nodeName, operationName)
}

func (oe *operationExecutor) DetachVolume(volumeToDetach AttachedVolume, verifySafeToDetach bool, actualStateOfWorld ActualStateOfWorldAttacherUpdater) error {
	generatedOperations, err :=
		oe.operationGenerator.GenerateDetachVolumeFunc(volumeToDetach, verifySafeToDetach, actualStateOfWorld)
	if err != nil {
		return err
	}

	if util.IsMultiAttachAllowed(volumeToDetach.VolumeSpec) {
		return oe.pendingOperations.Run(
			volumeToDetach.VolumeName, "" /* podName */, volumeToDetach.NodeName, generatedOperations)
	}
	return oe.pendingOperations.Run(
		volumeToDetach.VolumeName, "" /* podName */, "" /* nodeName */, generatedOperations)

}

func (oe *operationExecutor) VerifyVolumesAreAttached(attachedVolumes map[types.NodeName][]AttachedVolume, actualStateOfWorld ActualStateOfWorldAttacherUpdater) {

	// A map of plugin names and nodes on which they exist with volumes they manage
	bulkVerifyPluginsByNode := make(map[string]map[types.NodeName][]*volume.Spec)
	volumeSpecMapByPlugin := make(map[string]map[*volume.Spec]v1.UniqueVolumeName)

	for node, nodeAttachedVolumes := range attachedVolumes {
		needIndividualVerifyVolumes := []AttachedVolume{}
		for _, volumeAttached := range nodeAttachedVolumes {
			if volumeAttached.VolumeSpec == nil {
				klog.Errorf("VerifyVolumesAreAttached: nil spec for volume %s", volumeAttached.VolumeName)
				continue
			}

			volumePlugin, err :=
				oe.operationGenerator.GetVolumePluginMgr().FindPluginBySpec(volumeAttached.VolumeSpec)
			if err != nil {
				klog.Errorf(
					"VolumesAreAttached.FindPluginBySpec failed for volume %q (spec.Name: %q) on node %q with error: %v",
					volumeAttached.VolumeName,
					volumeAttached.VolumeSpec.Name(),
					volumeAttached.NodeName,
					err)
				continue
			}
			if volumePlugin == nil {
				// should never happen since FindPluginBySpec always returns error if volumePlugin = nil
				klog.Errorf(
					"Failed to find volume plugin for volume %q (spec.Name: %q) on node %q",
					volumeAttached.VolumeName,
					volumeAttached.VolumeSpec.Name(),
					volumeAttached.NodeName)
				continue
			}

			pluginName := volumePlugin.GetPluginName()

			if volumePlugin.SupportsBulkVolumeVerification() {
				pluginNodes, pluginNodesExist := bulkVerifyPluginsByNode[pluginName]

				if !pluginNodesExist {
					pluginNodes = make(map[types.NodeName][]*volume.Spec)
				}

				volumeSpecList, nodeExists := pluginNodes[node]
				if !nodeExists {
					volumeSpecList = []*volume.Spec{}
				}
				volumeSpecList = append(volumeSpecList, volumeAttached.VolumeSpec)
				pluginNodes[node] = volumeSpecList

				bulkVerifyPluginsByNode[pluginName] = pluginNodes
				volumeSpecMap, mapExists := volumeSpecMapByPlugin[pluginName]

				if !mapExists {
					volumeSpecMap = make(map[*volume.Spec]v1.UniqueVolumeName)
				}
				volumeSpecMap[volumeAttached.VolumeSpec] = volumeAttached.VolumeName
				volumeSpecMapByPlugin[pluginName] = volumeSpecMap
				continue
			}
			// If node doesn't support Bulk volume polling it is best to poll individually
			needIndividualVerifyVolumes = append(needIndividualVerifyVolumes, volumeAttached)
		}
		nodeError := oe.VerifyVolumesAreAttachedPerNode(needIndividualVerifyVolumes, node, actualStateOfWorld)
		if nodeError != nil {
			klog.Errorf("VerifyVolumesAreAttached failed for volumes %v, node %q with error %v", needIndividualVerifyVolumes, node, nodeError)
		}
	}

	for pluginName, pluginNodeVolumes := range bulkVerifyPluginsByNode {
		generatedOperations, err := oe.operationGenerator.GenerateBulkVolumeVerifyFunc(
			pluginNodeVolumes,
			pluginName,
			volumeSpecMapByPlugin[pluginName],
			actualStateOfWorld)
		if err != nil {
			klog.Errorf("BulkVerifyVolumes.GenerateBulkVolumeVerifyFunc error bulk verifying volumes for plugin %q with  %v", pluginName, err)
		}

		// Ugly hack to ensure - we don't do parallel bulk polling of same volume plugin
		uniquePluginName := v1.UniqueVolumeName(pluginName)
		err = oe.pendingOperations.Run(uniquePluginName, "" /* Pod Name */, "" /* nodeName */, generatedOperations)
		if err != nil {
			klog.Errorf("BulkVerifyVolumes.Run Error bulk volume verification for plugin %q  with %v", pluginName, err)
		}
	}
}

func (oe *operationExecutor) VerifyVolumesAreAttachedPerNode(attachedVolumes []AttachedVolume, nodeName types.NodeName, actualStateOfWorld ActualStateOfWorldAttacherUpdater) error {
	generatedOperations, err :=
		oe.operationGenerator.GenerateVolumesAreAttachedFunc(attachedVolumes, nodeName, actualStateOfWorld)
	if err != nil {
		return err
	}

	// Give an empty UniqueVolumeName so that this operation could be executed concurrently.
	return oe.pendingOperations.Run("" /* volumeName */, "" /* podName */, "" /* nodeName */, generatedOperations)
}

func (oe *operationExecutor) UnmountDevice(deviceToDetach AttachedVolume, actualStateOfWorld ActualStateOfWorldMounterUpdater, hostutil hostutil.HostUtils) error {
	fsVolume, err := util.CheckVolumeModeFilesystem(deviceToDetach.VolumeSpec)
	if err != nil {
		return err
	}
	var generatedOperations volumetypes.GeneratedOperations
	if fsVolume {
		// Filesystem volume case
		// Unmount and detach a device if a volume isn't referenced
		generatedOperations, err = oe.operationGenerator.GenerateUnmountDeviceFunc(deviceToDetach, actualStateOfWorld, hostutil)
	} else {
		// Block volume case
		// Detach a device and remove loopback if a volume isn't referenced
		generatedOperations, err = oe.operationGenerator.GenerateUnmapDeviceFunc(deviceToDetach, actualStateOfWorld, hostutil)
	}
	if err != nil {
		return err
	}
	// Avoid executing unmount/unmap device from multiple pods referencing
	// the same volume in parallel
	podName := nestedpendingoperations.EmptyUniquePodName

	return oe.pendingOperations.Run(
		deviceToDetach.VolumeName, podName, "" /* nodeName */, generatedOperations)
}

// ReconstructVolumeOperation return a func to create volumeSpec from mount path
func (oe *operationExecutor) ReconstructVolumeOperation(volumeMode v1.PersistentVolumeMode, plugin volume.VolumePlugin, mapperPlugin volume.BlockVolumePlugin, uid types.UID, podName volumetypes.UniquePodName, volumeSpecName string, volumePath string, pluginName string) (volume.ReconstructedVolume, error) {

	// Filesystem Volume case
	if volumeMode == v1.PersistentVolumeFilesystem {
		// Create volumeSpec from mount path
		klog.V(5).Infof("Starting operationExecutor.ReconstructVolume for file volume on pod %q", podName)
		reconstructed, err := plugin.ConstructVolumeSpec(volumeSpecName, volumePath)
		if err != nil {
			return volume.ReconstructedVolume{}, err
		}
		return reconstructed, nil
	}

	// Block Volume case
	// Create volumeSpec from mount path
	klog.V(5).Infof("Starting operationExecutor.ReconstructVolume for block volume on pod %q", podName)

	// volumePath contains volumeName on the path. In the case of block volume, {volumeName} is symbolic link
	// corresponding to raw block device.
	// ex. volumePath: pods/{podUid}}/{DefaultKubeletVolumeDevicesDirName}/{escapeQualifiedPluginName}/{volumeName}
	volumeSpec, err := mapperPlugin.ConstructBlockVolumeSpec(uid, volumeSpecName, volumePath)
	if err != nil {
		return volume.ReconstructedVolume{}, err
	}
	return volume.ReconstructedVolume{
		Spec: volumeSpec,
	}, nil
}

// CheckVolumeExistenceOperation checks mount path directory if volume still exists
func (oe *operationExecutor) CheckVolumeExistenceOperation(volumeSpec *volume.Spec, mountPath, volumeName string, mounter mount.Interface, uniqueVolumeName v1.UniqueVolumeName, podName volumetypes.UniquePodName, podUID types.UID, attachable volume.AttachableVolumePlugin) (bool, error) {
	fsVolume, err := util.CheckVolumeModeFilesystem(volumeSpec)
	if err != nil {
		return false, err
	}

	// Filesystem Volume case
	// For attachable volume case, check mount path directory if volume is still existing and mounted.
	// Return true if volume is mounted.
	if fsVolume {
		if attachable != nil {
			var isNotMount bool
			var mountCheckErr error
			if mounter == nil {
				return false, fmt.Errorf("mounter was not set for a filesystem volume")
			}
			if isNotMount, mountCheckErr = mount.IsNotMountPoint(mounter, mountPath); mountCheckErr != nil {
				return false, fmt.Errorf("could not check whether the volume %q (spec.Name: %q) pod %q (UID: %q) is mounted with: %v",
					uniqueVolumeName,
					volumeName,
					podName,
					podUID,
					mountCheckErr)
			}
			return !isNotMount, nil
		}
		// For non-attachable volume case, skip check and return true without mount point check
		// since plugins may not have volume mount point.
		return true, nil
	}

	// Block Volume case
	// Check mount path directory if volume still exists, then return true if volume
	// is there. Either plugin is attachable or non-attachable, the plugin should
	// have symbolic link associated to raw block device under pod device map
	// if volume exists.
	blkutil := volumepathhandler.NewBlockVolumePathHandler()
	var islinkExist bool
	var checkErr error
	if islinkExist, checkErr = blkutil.IsSymlinkExist(mountPath); checkErr != nil {
		return false, fmt.Errorf("could not check whether the block volume %q (spec.Name: %q) pod %q (UID: %q) is mapped to: %v",
			uniqueVolumeName,
			volumeName,
			podName,
			podUID,
			checkErr)
	}
	return islinkExist, nil
}

// ------------------------------------------------------------------------------------------------------------------

func (oe *operationExecutor) MountVolume(waitForAttachTimeout time.Duration, volumeToMount VolumeToMount, actualStateOfWorld ActualStateOfWorldMounterUpdater, isRemount bool) error {
	// 卷没有被挂载,或者已经被挂载,但需要重新挂载.
	fsVolume, err := util.CheckVolumeModeFilesystem(volumeToMount.VolumeSpec)
	if err != nil {
		return err
	}
	var generatedOperations volumetypes.GeneratedOperations
	if fsVolume {
		// Filesystem volume case
		// Mount/remount a volume when a volume is attached
		generatedOperations = oe.operationGenerator.GenerateMountVolumeFunc(waitForAttachTimeout, volumeToMount, actualStateOfWorld, isRemount)
	} else {
		// Block volume case
		// Creates a map to device if a volume is attached
		generatedOperations, err = oe.operationGenerator.GenerateMapVolumeFunc(waitForAttachTimeout, volumeToMount, actualStateOfWorld)
	}
	if err != nil {
		return err
	}
	// Avoid executing mount/map from multiple pods referencing the
	// same volume in parallel
	podName := nestedpendingoperations.EmptyUniquePodName

	// TODO: remove this -- not necessary
	if !volumeToMount.PluginIsAttachable && !volumeToMount.PluginIsDeviceMountable {
		// volume plugins which are Non-attachable and Non-deviceMountable can execute mount for multiple pods
		// referencing the same volume in parallel
		podName = util.GetUniquePodName(volumeToMount.Pod)
	}

	// TODO mount_device
	return oe.pendingOperations.Run(volumeToMount.VolumeName, podName, "" /* nodeName */, generatedOperations)
}

// UnmountVolume
// 'Filesystem' volumeMode,UnmountVolume方法会从volumeToUnmount中指定的pod中卸载该卷,并更新实际状态以反映此操作.
//
//	'Block' volumeMode,此方法将从volumeToUnmount中指定的pod设备映射路径和全局映射路径中取消卷的符号链接.然后,更新实际状态以反映此操作.
func (oe *operationExecutor) UnmountVolume(volumeToUnmount MountedVolume, actualStateOfWorld ActualStateOfWorldMounterUpdater, podsDir string) error { // ✅
	fsVolume, err := util.CheckVolumeModeFilesystem(volumeToUnmount.VolumeSpec)
	if err != nil {
		return err
	}
	var generatedOperations volumetypes.GeneratedOperations
	if fsVolume {
		// 卸载该文件系统.
		// 获取当前系统中所有已挂载的文件系统信息,可以通过读取/proc/mounts文件来获取；
		// 检查是否存在指定的文件系统,可以根据文件系统的设备名或挂载点来判断；
		// 如果指定的文件系统已经挂载,则卸载该文件系统,可以使用umount命令来卸载文件系统.
		generatedOperations, err = oe.operationGenerator.GenerateUnmountVolumeFunc(volumeToUnmount, actualStateOfWorld, podsDir)
	} else {
		// Block volume case
		// Unmap a volume if a volume is mapped
		generatedOperations, err = oe.operationGenerator.GenerateUnmapVolumeFunc(volumeToUnmount, actualStateOfWorld)
	}
	if err != nil {
		return err
	}
	// All volume plugins can execute unmount/unmap for multiple pods referencing the
	// same volume in parallel
	podName := volumetypes.UniquePodName(volumeToUnmount.PodUID)

	return oe.pendingOperations.Run(volumeToUnmount.VolumeName, podName, "" /* nodeName */, generatedOperations)
}

func (oe *operationExecutor) VerifyControllerAttachedVolume(volumeToMount VolumeToMount, nodeName types.NodeName, actualStateOfWorld ActualStateOfWorldAttacherUpdater) error {
	generatedOperations, err := oe.operationGenerator.GenerateVerifyControllerAttachedVolumeFunc(volumeToMount, nodeName, actualStateOfWorld)
	if err != nil {
		return err
	}

	return oe.pendingOperations.Run(volumeToMount.VolumeName, "" /* podName */, "" /* nodeName */, generatedOperations)
}

// ExpandInUseVolume 将卷的文件系统大小调整为预期大小,而不卸载卷.
func (oe *operationExecutor) ExpandInUseVolume(volumeToMount VolumeToMount, actualStateOfWorld ActualStateOfWorldMounterUpdater, currentSize resource.Quantity) error {
	generatedOperations, err := oe.operationGenerator.GenerateExpandInUseVolumeFunc(volumeToMount, actualStateOfWorld, currentSize)
	if err != nil {
		return err
	}
	return oe.pendingOperations.Run(volumeToMount.VolumeName, "", "" /* nodeName */, generatedOperations)
}

func (oe *operationExecutor) AttachVolume( // ✅
	volumeToAttach VolumeToAttach, actualStateOfWorld ActualStateOfWorldAttacherUpdater) error {
	generatedOperations := oe.operationGenerator.GenerateAttachVolumeFunc(volumeToAttach, actualStateOfWorld)

	if util.IsMultiAttachAllowed(volumeToAttach.VolumeSpec) { // ✅
		return oe.pendingOperations.Run(volumeToAttach.VolumeName, "" /* podName */, volumeToAttach.NodeName, generatedOperations)
	}

	return oe.pendingOperations.Run(volumeToAttach.VolumeName, "" /* podName */, "" /* nodeName */, generatedOperations)
}
