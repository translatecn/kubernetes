/*
Copyright 2014 The Kubernetes Authors.

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

package volume

import (
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type Volume interface { // 节点上Pod或主机使用的目录
	GetPath() string // pod 的volume 应该挂载到那个目录
	MetricsProvider
}

// BlockVolume interface provides methods to generate global map path
// and pod device map path.
type BlockVolume interface {
	// GetGlobalMapPath 返回一个全局映射路径,其中包含与块设备相关联的绑定挂载.这意味着返回一个包含块设备绑定挂载的全局路径.
	// ex. plugins/kubernetes.io/{PluginName}/{DefaultKubeletVolumeDevicesDirName}/{volumePluginDependentPath}/{pod uuid}
	GetGlobalMapPath(spec *Spec) (string, error)
	// GetPodDeviceMapPath returns a pod device map path
	// and name of a symbolic link associated to a block device.
	// ex. pods/{podUid}/{DefaultKubeletVolumeDevicesDirName}/{escapeQualifiedPluginName}/, {volumeName}
	GetPodDeviceMapPath() (string, string)

	// SupportsMetrics should return true if the MetricsProvider is
	// initialized
	SupportsMetrics() bool

	// MetricsProvider embeds methods for exposing metrics (e.g.
	// used, available space).
	MetricsProvider
}

// MetricsProvider exposes metrics (e.g. used,available space) related to a
// Volume.
type MetricsProvider interface {
	// GetMetrics returns the Metrics for the Volume. Maybe expensive for
	// some implementations.
	GetMetrics() (*Metrics, error)
}

// Metrics represents the used and available bytes of the Volume.
type Metrics struct {
	// The time at which these stats were updated.
	Time metav1.Time

	// Used represents the total bytes used by the Volume.
	// Note: For block devices this maybe more than the total size of the files.
	Used *resource.Quantity

	// Capacity represents the total capacity (bytes) of the volume's
	// underlying storage. For Volumes that share a filesystem with the host
	// (e.g. emptydir, hostpath) this is the size of the underlying storage,
	// and will not equal Used + Available as the fs is shared.
	Capacity *resource.Quantity

	// Available represents the storage space available (bytes) for the
	// Volume. For Volumes that share a filesystem with the host (e.g.
	// emptydir, hostpath), this is the available space on the underlying
	// storage, and is shared with host processes and other Volumes.
	Available *resource.Quantity

	// InodesUsed represents the total inodes used by the Volume.
	InodesUsed *resource.Quantity

	// Inodes represents the total number of inodes available in the volume.
	// For volumes that share a filesystem with the host (e.g. emptydir, hostpath),
	// this is the inodes available in the underlying storage,
	// and will not equal InodesUsed + InodesFree as the fs is shared.
	Inodes *resource.Quantity

	// InodesFree represent the inodes available for the volume.  For Volumes that share
	// a filesystem with the host (e.g. emptydir, hostpath), this is the free inodes
	// on the underlying storage, and is shared with host processes and other volumes
	InodesFree *resource.Quantity

	// Normal volumes are available for use and operating optimally.
	// An abnormal volume does not meet these criteria.
	// This field is OPTIONAL. Only some csi drivers which support NodeServiceCapability_RPC_VOLUME_CONDITION
	// need to fill it.
	Abnormal *bool

	// The message describing the condition of the volume.
	// This field is OPTIONAL. Only some csi drivers which support capability_RPC_VOLUME_CONDITION
	// need to fill it.
	Message *string
}

// Attributes represents the attributes of this mounter.
type Attributes struct {
	ReadOnly       bool
	Managed        bool
	SELinuxRelabel bool
}

type MounterArgs struct {
	FsUser              *int64
	FsGroup             *int64
	FSGroupChangePolicy *v1.PodFSGroupChangePolicy // 指定是否允许在运行时修改文件系统的组 ID（GID）,以及何时允许进行修改.可选的值包括 Never、OnRootMismatch 和 Always.
	DesiredSize         *resource.Quantity         // 指定挂载卷的期望大小,以便在挂载前进行预分配空间.
	SELinuxLabel        string                     // 指定挂载卷后文件系统的 SELinux 标签,用于控制访问权限和安全策略.
}

// Mounter interface provides methods to set up/mount the volume.
type Mounter interface {
	// Uses Interface to provide the path for Docker binds.
	Volume

	// SetUp prepares and mounts/unpacks the volume to a
	// self-determined directory path. The mount point and its
	// content should be owned by `fsUser` or 'fsGroup' so that it can be
	// accessed by the pod. This may be called more than once, so
	// implementations must be idempotent.
	// It could return following types of errors:
	//   - TransientOperationFailure
	//   - UncertainProgressError
	//   - Error of any other type should be considered a final error
	SetUp(mounterArgs MounterArgs) error

	// SetUpAt prepares and mounts/unpacks the volume to the
	// specified directory path, which may or may not exist yet.
	// The mount point and its content should be owned by `fsUser`
	// 'fsGroup' so that it can be accessed by the pod. This may
	// be called more than once, so implementations must be
	// idempotent.
	SetUpAt(dir string, mounterArgs MounterArgs) error
	// GetAttributes returns the attributes of the mounter.
	// This function is called after SetUp()/SetUpAt().
	GetAttributes() Attributes
}

type Unmounter interface {
	Volume
	TearDown() error             // 从自行确定的目录卸载卷,并删除SetUp过程的痕迹.
	TearDownAt(dir string) error // 从指定的目录卸载卷,并删除SetUp过程的痕迹.
}

// BlockVolumeMapper interface is a mapper interface for block volume.
type BlockVolumeMapper interface {
	BlockVolume
}

// CustomBlockVolumeMapper interface provides custom methods to set up/map the volume.
type CustomBlockVolumeMapper interface {
	BlockVolumeMapper
	// SetUpDevice prepares the volume to the node by the plugin specific way.
	// For most in-tree plugins, attacher.Attach() and attacher.WaitForAttach()
	// will do necessary works.
	// This may be called more than once, so implementations must be idempotent.
	// SetUpDevice returns stagingPath if device setup was successful
	SetUpDevice() (stagingPath string, err error)
	// MapPodDevice 将块设备映射到一个路径并返回该路径.为了避免意外的块卷销毁,需要在 kubelet 节点重新启动时保证设备路径的唯一性.
	MapPodDevice() (publishPath string, err error)

	// GetStagingPath returns path that was used for staging the volume
	// it is mainly used by CSI plugins
	GetStagingPath() string
}

// BlockVolumeUnmapper interface is an unmapper interface for block volume.
type BlockVolumeUnmapper interface {
	BlockVolume
}

// CustomBlockVolumeUnmapper interface provides custom methods to cleanup/unmap the volumes.
type CustomBlockVolumeUnmapper interface {
	BlockVolumeUnmapper
	// TearDownDevice removes traces of the SetUpDevice procedure.
	// If the plugin is non-attachable, this method detaches the volume
	// from a node.
	TearDownDevice(mapPath string, devicePath string) error

	// UnmapPodDevice removes traces of the MapPodDevice procedure.
	UnmapPodDevice() error
}

// Provisioner is an interface that creates templates for PersistentVolumes
// and can create the volume as a new resource in the infrastructure provider.
type Provisioner interface {
	// Provision creates the resource by allocating the underlying volume in a
	// storage system. This method should block until completion and returns
	// PersistentVolume representing the created storage resource.
	Provision(selectedNode *v1.Node, allowedTopologies []v1.TopologySelectorTerm) (*v1.PersistentVolume, error)
}

// Deleter removes the resource from the underlying storage provider. Calls
// to this method should block until the deletion is complete. Any error
// returned indicates the volume has failed to be reclaimed. A nil return
// indicates success.
type Deleter interface {
	Volume
	// This method should block until completion.
	// deletedVolumeInUseError returned from this function will not be reported
	// as error and it will be sent as "Info" event to the PV being deleted. The
	// volume controller will retry deleting the volume in the next periodic
	// sync. This can be used to postpone deletion of a volume that is being
	// detached from a node. Deletion of such volume would fail anyway and such
	// error would confuse users.
	Delete() error
}

// Attacher 将卷挂载到一个节点上
type Attacher interface {
	DeviceMounter
	Attach(spec *Spec, nodeName types.NodeName) (string, error)                                      // 将卷连接到指定名称的节点上.连接成功后,返回设备连接到节点上的设备路径.
	VolumesAreAttached(specs []*Spec, nodeName types.NodeName) (map[*Spec]bool, error)               // 检查指定节点上仍连接的卷列表.
	WaitForAttach(spec *Spec, devicePath string, pod *v1.Pod, timeout time.Duration) (string, error) // 阻塞直到设备连接到此节点.如果它成功连接,将返回设备的路径.否则,如果在给定的超时期间内设备未连接,则会返回错误.
}

// DeviceMounterArgs provides auxiliary, optional arguments to DeviceMounter.
type DeviceMounterArgs struct {
	FsGroup      *int64
	SELinuxLabel string
}

// DeviceMounter 挂载的是设备,例如磁盘或分区,它可以将设备挂载到主机的文件系统中.
type DeviceMounter interface {
	// GetDeviceMountPath 获取设备挂载的路径,当设备附加后应该挂载到哪个目录下.这个路径是全局的,需要为每个卷进行绑定挂载.
	GetDeviceMountPath(spec *Spec) (string, error)
	// MountDevice 将磁盘挂载到全局路径上,然后让每个 Pod 将其绑定挂载到自己的目录下.
	MountDevice(spec *Spec, devicePath string, deviceMountPath string, deviceMounterArgs DeviceMounterArgs) error
}

type BulkVolumeVerifier interface {
	// BulkVerifyVolumes checks whether the list of volumes still attached to the
	// clusters in the node. It returns a map which maps from the volume spec to the checking result.
	// If an error occurs during check - error should be returned and volume on nodes
	// should be assumed as still attached.
	BulkVerifyVolumes(volumesByNode map[types.NodeName][]*Spec) (map[types.NodeName]map[*Spec]bool, error)
}

// Detacher can detach a volume from a node.
type Detacher interface {
	DeviceUnmounter
	// Detach the given volume from the node with the given Name.
	// volumeName is name of the volume as returned from plugin's
	// GetVolumeName().
	Detach(volumeName string, nodeName types.NodeName) error
}

// DeviceUnmounter can unmount a block volume from the global path.
type DeviceUnmounter interface {
	// UnmountDevice unmounts the global mount of the disk. This
	// should only be called once all bind mounts have been
	// unmounted.
	UnmountDevice(deviceMountPath string) error
}
