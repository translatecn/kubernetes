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
	"k8s.io/klog/v2"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/util/feature"
	"k8s.io/component-base/metrics"
	apiv1resource "k8s.io/kubernetes/pkg/api/v1/resource"
	"k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/pkg/volume"
	"k8s.io/kubernetes/pkg/volume/util"
	"k8s.io/kubernetes/pkg/volume/util/operationexecutor"
	"k8s.io/kubernetes/pkg/volume/util/types"
)

// DesiredStateOfWorld defines a set of thread-safe operations for the kubelet
// volume manager's desired state of the world cache.
// This cache contains volumes->pods i.e. a set of all volumes that should be
// attached to this node and the pods that reference them and should mount the
// volume.
// Note: This is distinct from the DesiredStateOfWorld implemented by the
// attach/detach controller. They both keep track of different objects. This
// contains kubelet volume manager specific state.
type DesiredStateOfWorld interface {
	// AddPodToVolume 这段代码是一个函数,功能是将给定的 pod 添加到给定的 volume 中,并在缓存中指示指定的 pod 应该挂载指定的 volume.
	// 成功后,从 volumeSpec 生成一个唯一的 volumeName 并返回.
	// 如果没有 volume 插件能够支持给定的 volumeSpec 或者多个插件都能支持它,则返回错误.
	// 如果在应该附加到此节点的卷列表中不存在名称为 volumeName 的卷,则会隐式添加该卷.
	// 如果指定卷下已经存在具有相同唯一名称的 pod,则不执行任何操作.
	AddPodToVolume(podName types.UniquePodName, pod *v1.Pod, volumeSpec *volume.Spec, outerVolumeSpecName string, volumeGidValue string, seLinuxContainerContexts []*v1.SELinuxOptions) (v1.UniqueVolumeName, error)

	// MarkVolumesReportedInUse 该卷已成功添加到节点状态中的VolumesInUse字段中
	MarkVolumesReportedInUse(reportedVolumes []v1.UniqueVolumeName)

	// DeletePodFromVolume removes the given pod from the given volume in the
	// cache indicating the specified pod no longer requires the specified
	// volume.
	// If a pod with the same unique name does not exist under the specified
	// volume, this is a no-op.
	// If a volume with the name volumeName does not exist in the list of
	// attached volumes, this is a no-op.
	// If after deleting the pod, the specified volume contains no other child
	// pods, the volume is also deleted.
	DeletePodFromVolume(podName types.UniquePodName, volumeName v1.UniqueVolumeName)

	// VolumeExists returns true if the given volume exists in the list of
	// volumes that should be attached to this node.
	// If a pod with the same unique name does not exist under the specified
	// volume, false is returned.
	VolumeExists(volumeName v1.UniqueVolumeName, seLinuxMountContext string) bool

	// PodExistsInVolume returns true if the given pod exists in the list of
	// podsToMount for the given volume in the cache.
	// If a pod with the same unique name does not exist under the specified
	// volume, false is returned.
	// If a volume with the name volumeName does not exist in the list of
	// attached volumes, false is returned.
	PodExistsInVolume(podName types.UniquePodName, volumeName v1.UniqueVolumeName, seLinuxMountContext string) bool

	// GetVolumesToMount 生成并返回一个卷列表,该列表应该附加到此节点并应该被挂载到哪些Pod上,该列表基于当前的期望世界状态.
	GetVolumesToMount() []VolumeToMount

	// GetPods generates and returns a map of pods in which map is indexed
	// with pod's unique name. This map can be used to determine which pod is currently
	// in desired state of world.
	GetPods() map[types.UniquePodName]bool

	// VolumeExistsWithSpecName returns true if the given volume specified with the
	// volume spec name (a.k.a., InnerVolumeSpecName) exists in the list of
	// volumes that should be attached to this node.
	// If a pod with the same name does not exist under the specified
	// volume, false is returned.
	VolumeExistsWithSpecName(podName types.UniquePodName, volumeSpecName string) bool

	// AddErrorToPod adds the given error to the given pod in the cache.
	// It will be returned by subsequent GetPodErrors().
	// Each error string is stored only once.
	AddErrorToPod(podName types.UniquePodName, err string)
	PopPodErrors(podName types.UniquePodName) []string // 返回挂载出现的所有问题

	// GetPodsWithErrors returns names of pods that have stored errors.
	GetPodsWithErrors() []types.UniquePodName

	// MarkVolumeAttachability 记录挂载状态
	MarkVolumeAttachability(volumeName v1.UniqueVolumeName, attachable bool)
	// UpdatePersistentVolumeSize 在期望的世界状态中更新persistentVolumeSize,以便可以将其与实际大小进行
	UpdatePersistentVolumeSize(volumeName v1.UniqueVolumeName, size *resource.Quantity)
}

// VolumeToMount represents a volume that is attached to this node and needs to
// be mounted to PodName.
type VolumeToMount struct {
	operationexecutor.VolumeToMount
}

// NewDesiredStateOfWorld returns a new instance of DesiredStateOfWorld.
func NewDesiredStateOfWorld(volumePluginMgr *volume.VolumePluginMgr, seLinuxTranslator util.SELinuxLabelTranslator) DesiredStateOfWorld {
	if feature.DefaultFeatureGate.Enabled(features.SELinuxMountReadWriteOncePod) {
		registerSELinuxMetrics()
	}
	return &desiredStateOfWorld{
		volumesToMount:    make(map[v1.UniqueVolumeName]volumeToMount),
		volumePluginMgr:   volumePluginMgr,
		podErrors:         make(map[types.UniquePodName]sets.String),
		seLinuxTranslator: seLinuxTranslator,
	}
}

type desiredStateOfWorld struct {
	volumesToMount    map[v1.UniqueVolumeName]volumeToMount // 包含应该挂载到该节点并且被引用的 Pod 所使用的卷的集合.映射的键是卷的名称,值是一个包含有关卷的更多信息的卷对象.
	volumePluginMgr   *volume.VolumePluginMgr
	podErrors         map[types.UniquePodName]sets.String
	seLinuxTranslator util.SELinuxLabelTranslator // 将 v1.SELinuxOptions 翻译成文件 SELinux 标签的 SELinux 标签翻译器.
	sync.RWMutex
}

// 应该挂载到该节点并挂载到 podsToMount 的卷
type volumeToMount struct {
	volumeName              v1.UniqueVolumeName
	podsToMount             map[types.UniquePodName]podToMount // 引用该卷并在挂载后应该挂载它的 Pod 的集合
	pluginIsAttachable      bool                               // 该卷的插件是否实现了 volume.Attacher 接口.
	pluginIsDeviceMountable bool                               // 该卷的插件是否实现了 volume.DeviceMounter 接口.
	volumeGidValue          string                             // 卷的 GID 注释的值
	reportedInUse           bool                               // 指示该卷是否已成功添加到节点状态的 VolumesInUse 字段中.
	desiredSizeLimit        *resource.Quantity                 // 指示该卷的大小上限（如果实现了）.
	persistentVolumeSize    *resource.Quantity                 // 记录持久卷的期望大小.通常,该值反映在 pv.Spec.Capacity 中记录的大小.

	// seLinuxFileLabel is desired SELinux label on files on the volume. If empty, then
	// - either the context+label is unknown (assigned randomly by the container runtime)
	// - or the volume plugin responsible for this volume does not support mounting with -o context
	// - or the OS does not support SELinux
	// In all cases, the SELinux context does not matter when mounting the volume.
	seLinuxFileLabel string
}

// The pod object represents a pod that references the underlying volume and
// should mount it once it is attached.
type podToMount struct {
	// podName contains the name of this pod.
	podName types.UniquePodName

	// Pod to mount the volume to. Used to create NewMounter.
	pod *v1.Pod

	// volume spec containing the specification for this volume. Used to
	// generate the volume plugin object, and passed to plugin methods.
	// For non-PVC volumes this is the same as defined in the pod object. For
	// PVC volumes it is from the dereferenced PV object.
	volumeSpec *volume.Spec

	// outerVolumeSpecName is the volume.Spec.Name() of the volume as referenced
	// directly in the pod. If the volume was referenced through a persistent
	// volume claim, this contains the volume.Spec.Name() of the persistent
	// volume claim
	outerVolumeSpecName string
	// mountRequestTime stores time at which mount was requested
	mountRequestTime time.Time
}

const (
	// Maximum errors to be stored per pod in desiredStateOfWorld.podErrors to
	// prevent unbound growth.
	maxPodErrors = 10
)

func (dsw *desiredStateOfWorld) MarkVolumesReportedInUse(reportedVolumes []v1.UniqueVolumeName) {
	dsw.Lock()
	defer dsw.Unlock()

	reportedVolumesMap := make(
		map[v1.UniqueVolumeName]bool, len(reportedVolumes) /* capacity */)

	for _, reportedVolume := range reportedVolumes {
		reportedVolumesMap[reportedVolume] = true
	}

	for volumeName, volumeObj := range dsw.volumesToMount {
		_, volumeReported := reportedVolumesMap[volumeName]
		volumeObj.reportedInUse = volumeReported
		dsw.volumesToMount[volumeName] = volumeObj
	}
}

// UpdatePersistentVolumeSize updates last known PV size. This is used for volume expansion and
// should be only used for persistent volumes.
func (dsw *desiredStateOfWorld) UpdatePersistentVolumeSize(volumeName v1.UniqueVolumeName, size *resource.Quantity) {
	dsw.Lock()
	defer dsw.Unlock()

	vol, volExists := dsw.volumesToMount[volumeName]
	if volExists {
		vol.persistentVolumeSize = size
		dsw.volumesToMount[volumeName] = vol
	}
}

func (dsw *desiredStateOfWorld) VolumeExists(
	volumeName v1.UniqueVolumeName, seLinuxMountContext string) bool {
	dsw.RLock()
	defer dsw.RUnlock()

	vol, volumeExists := dsw.volumesToMount[volumeName]
	if !volumeExists {
		return false
	}
	if feature.DefaultFeatureGate.Enabled(features.SELinuxMountReadWriteOncePod) {
		// Handling two volumes with the same name and different SELinux context
		// as two *different* volumes here. Because if a volume is mounted with
		// an old SELinux context, it must be unmounted first and then mounted again
		// with the new context.
		//
		// This will happen when a pod A with context alpha_t runs and is being
		// terminated by kubelet and its volumes are being torn down, while a
		// pod B with context beta_t is already scheduled on the same node,
		// using the same volumes
		// The volumes from Pod A must be fully unmounted (incl. UnmountDevice)
		// and mounted with new SELinux mount options for pod B.
		// Without SELinux, kubelet can (and often does) reuse device mounted
		// for A.
		return vol.seLinuxFileLabel == seLinuxMountContext
	}
	return true
}

func (dsw *desiredStateOfWorld) PodExistsInVolume(
	podName types.UniquePodName, volumeName v1.UniqueVolumeName, seLinuxMountOption string) bool {
	dsw.RLock()
	defer dsw.RUnlock()

	volumeObj, volumeExists := dsw.volumesToMount[volumeName]
	if !volumeExists {
		return false
	}

	if feature.DefaultFeatureGate.Enabled(features.SELinuxMountReadWriteOncePod) {
		if volumeObj.seLinuxFileLabel != seLinuxMountOption {
			// The volume is in DSW, but with a different SELinux mount option.
			// Report it as unused, so the volume is unmounted and mounted back
			// with the right SELinux option.
			return false
		}
	}

	_, podExists := volumeObj.podsToMount[podName]
	return podExists
}

func (dsw *desiredStateOfWorld) VolumeExistsWithSpecName(podName types.UniquePodName, volumeSpecName string) bool {
	dsw.RLock()
	defer dsw.RUnlock()
	for _, volumeObj := range dsw.volumesToMount {
		if podObj, podExists := volumeObj.podsToMount[podName]; podExists {
			if podObj.volumeSpec.Name() == volumeSpecName {
				return true
			}
		}
	}
	return false
}

func (dsw *desiredStateOfWorld) GetPods() map[types.UniquePodName]bool {
	dsw.RLock()
	defer dsw.RUnlock()

	podList := make(map[types.UniquePodName]bool)
	for _, volumeObj := range dsw.volumesToMount {
		for podName := range volumeObj.podsToMount {
			podList[podName] = true
		}
	}
	return podList
}

func (dsw *desiredStateOfWorld) AddErrorToPod(podName types.UniquePodName, err string) {
	dsw.Lock()
	defer dsw.Unlock()

	if errs, found := dsw.podErrors[podName]; found {
		if errs.Len() <= maxPodErrors {
			errs.Insert(err)
		}
		return
	}
	dsw.podErrors[podName] = sets.NewString(err)
}

func (dsw *desiredStateOfWorld) PopPodErrors(podName types.UniquePodName) []string {
	dsw.Lock()
	defer dsw.Unlock()

	if errs, found := dsw.podErrors[podName]; found {
		delete(dsw.podErrors, podName)
		return errs.List()
	}
	return []string{}
}

func (dsw *desiredStateOfWorld) GetPodsWithErrors() []types.UniquePodName {
	dsw.RLock()
	defer dsw.RUnlock()

	pods := make([]types.UniquePodName, 0, len(dsw.podErrors))
	for podName := range dsw.podErrors {
		pods = append(pods, podName)
	}
	return pods
}

func (dsw *desiredStateOfWorld) MarkVolumeAttachability(volumeName v1.UniqueVolumeName, attachable bool) { // ✅
	dsw.Lock()
	defer dsw.Unlock()
	volumeObj, volumeExists := dsw.volumesToMount[volumeName]
	if !volumeExists {
		return
	}
	volumeObj.pluginIsAttachable = attachable
	dsw.volumesToMount[volumeName] = volumeObj
}

func (dsw *desiredStateOfWorld) getSELinuxMountSupport(volumeSpec *volume.Spec) (bool, error) { // ✅
	return util.SupportsSELinuxContextMount(volumeSpec, dsw.volumePluginMgr)
}

// Based on isRWOP, bump the right warning / error metric and either consume the error or return it.
func handleSELinuxMetricError(err error, seLinuxSupported bool, warningMetric, errorMetric *metrics.Gauge) error {
	if seLinuxSupported {
		errorMetric.Add(1.0)
		return err
	}

	// This is not an error yet, but it will be when support for other access modes is added.
	warningMetric.Add(1.0)
	klog.V(4).ErrorS(err, "Please report this error in https://github.com/kubernetes/enhancements/issues/1710, together with full Pod yaml file")
	return nil
}

func (dsw *desiredStateOfWorld) getSELinuxLabel(volumeSpec *volume.Spec, seLinuxContainerContexts []*v1.SELinuxOptions) (string, bool, error) {
	//   - name: my-container
	//    image: nginx
	//    securityContext:
	//      seLinuxOptions:
	//        level: s0:c123,c456
	//   该标签的级别为 s0,上下文为 c123 和 c456.这将允许该容器仅访问具有相同标签的对象,并防止其访问具有不同标签的对象.
	var seLinuxFileLabel string
	var pluginSupportsSELinuxContextMount bool

	if feature.DefaultFeatureGate.Enabled(features.SELinuxMountReadWriteOncePod) {
		var err error

		if !dsw.seLinuxTranslator.SELinuxEnabled() {
			return "", false, nil
		}

		pluginSupportsSELinuxContextMount, err = dsw.getSELinuxMountSupport(volumeSpec)
		if err != nil {
			return "", false, err
		}
		seLinuxSupported := util.VolumeSupportsSELinuxMount(volumeSpec)
		if pluginSupportsSELinuxContextMount {
			// Ensure that a volume that can be mounted with "-o context=XYZ" is
			// used only by containers with the same SELinux contexts.
			for _, containerContext := range seLinuxContainerContexts {
				newLabel, err := dsw.seLinuxTranslator.SELinuxOptionsToFileLabel(containerContext)
				if err != nil {
					fullErr := fmt.Errorf("failed to construct SELinux label from context %q: %s", containerContext, err)
					if err := handleSELinuxMetricError(fullErr, seLinuxSupported, seLinuxContainerContextWarnings, seLinuxContainerContextErrors); err != nil {
						return "", false, err
					}
				}
				if seLinuxFileLabel == "" {
					seLinuxFileLabel = newLabel
					continue
				}
				if seLinuxFileLabel != newLabel {
					fullErr := fmt.Errorf("volume %s is used with two different SELinux contexts in the same pod: %q, %q", volumeSpec.Name(), seLinuxFileLabel, newLabel)
					if err := handleSELinuxMetricError(fullErr, seLinuxSupported, seLinuxPodContextMismatchWarnings, seLinuxPodContextMismatchErrors); err != nil {
						return "", false, err
					}
				}
			}
		} else {
			// Volume plugin does not support SELinux context mount.
			// DSW will track this volume with SELinux label "", i.e. no mount with
			// -o context.
			seLinuxFileLabel = ""
		}
	}
	return seLinuxFileLabel, pluginSupportsSELinuxContextMount, nil
}

// AddPodToVolume 这段代码是一个函数,功能是将给定的 pod 添加到给定的 volume 中,并在缓存中指示指定的 pod 应该挂载指定的 volume.
// 成功后,从 volumeSpec 生成一个唯一的 volumeName 并返回.
// 如果没有 volume 插件能够支持给定的 volumeSpec 或者多个插件都能支持它,则返回错误.
// 如果在应该附加到此节点的卷列表中不存在名称为 volumeName 的卷,则会隐式添加该卷.
// 如果指定卷下已经存在具有相同唯一名称的 pod,则不执行任何操作.
func (dsw *desiredStateOfWorld) AddPodToVolume(
	podName types.UniquePodName,
	pod *v1.Pod,
	volumeSpec *volume.Spec,
	outerVolumeSpecName string,
	volumeGidValue string,
	seLinuxContainerContexts []*v1.SELinuxOptions) (v1.UniqueVolumeName, error) {
	dsw.Lock()
	defer dsw.Unlock()

	volumePlugin, err := dsw.volumePluginMgr.FindPluginBySpec(volumeSpec)
	if err != nil || volumePlugin == nil {
		return "", fmt.Errorf(
			"failed to get Plugin from volumeSpec for volume %q err=%v",
			volumeSpec.Name(),
			err)
	}

	var volumeName v1.UniqueVolumeName

	// 这段代码的意思是,生成的唯一卷名称取决于卷是否可附加/设备可挂载.如果卷是可附加/设备可挂载的,则生成的唯一卷名称将包含设备路径等信息,否则只包含卷名称等基本信息.
	attachable := util.IsAttachableVolume(volumeSpec, dsw.volumePluginMgr)
	deviceMountable := util.IsDeviceMountableVolume(volumeSpec, dsw.volumePluginMgr)
	if attachable || deviceMountable {
		// For attachable/device-mountable volumes, use the unique volume name as reported by
		// the plugin.
		volumeName, err = util.GetUniqueVolumeNameFromSpec(volumePlugin, volumeSpec)
		if err != nil {
			return "", fmt.Errorf(
				"failed to GetUniqueVolumeNameFromSpec for volumeSpec %q using volume plugin %q err=%v",
				volumeSpec.Name(),
				volumePlugin.GetPluginName(),
				err)
		}
	} else {
		// 对于不可附加和不可设备挂载的卷,将基于 Pod 命名空间和名称以及 Pod 中卷的名称生成一个唯一的名称.这是因为这种类型的卷不需要设备路径等信息,因此只需使用这些基本信息即可生成唯一名称.
		volumeName = util.GetUniqueVolumeNameFromSpecWithPod(podName, volumePlugin, volumeSpec)
	}

	seLinuxFileLabel, pluginSupportsSELinuxContextMount, err := dsw.getSELinuxLabel(volumeSpec, seLinuxContainerContexts)
	if err != nil {
		return "", err
	}
	klog.V(4).InfoS("expected volume SELinux label context", "volume", volumeSpec.Name(), "label", seLinuxFileLabel)

	// 期望的系统状态
	if vol, volumeExists := dsw.volumesToMount[volumeName]; !volumeExists {
		var sizeLimit *resource.Quantity //小的本地值
		if volumeSpec.Volume != nil {
			if util.IsLocalEphemeralVolume(*volumeSpec.Volume) {
				_, podLimits := apiv1resource.PodRequestsAndLimits(pod)
				ephemeralStorageLimit := podLimits[v1.ResourceEphemeralStorage]
				sizeLimit = resource.NewQuantity(ephemeralStorageLimit.Value(), resource.BinarySI)
				if volumeSpec.Volume.EmptyDir != nil &&
					volumeSpec.Volume.EmptyDir.SizeLimit != nil &&
					volumeSpec.Volume.EmptyDir.SizeLimit.Value() > 0 &&
					(sizeLimit.Value() == 0 || volumeSpec.Volume.EmptyDir.SizeLimit.Value() < sizeLimit.Value()) {
					sizeLimit = resource.NewQuantity(volumeSpec.Volume.EmptyDir.SizeLimit.Value(), resource.BinarySI)
				}
			}
		}
		if !util.VolumeSupportsSELinuxMount(volumeSpec) {
			// Clear SELinux label for the volume with unsupported access modes.
			klog.V(4).InfoS("volume does not support SELinux context mount, clearing the expected label", "volume", volumeSpec.Name())
			seLinuxFileLabel = ""
		}
		if seLinuxFileLabel != "" {
			seLinuxVolumesAdmitted.Add(1.0)
		}
		vmt := volumeToMount{
			volumeName:              volumeName,
			podsToMount:             make(map[types.UniquePodName]podToMount),
			pluginIsAttachable:      attachable,
			pluginIsDeviceMountable: deviceMountable,
			volumeGidValue:          volumeGidValue,
			reportedInUse:           false,
			desiredSizeLimit:        sizeLimit,
			seLinuxFileLabel:        seLinuxFileLabel,
		}
		// 记录所需的存储空间大小
		if volumeSpec.PersistentVolume != nil {
			pvCap := volumeSpec.PersistentVolume.Spec.Capacity.Storage()
			if pvCap != nil {
				pvCapCopy := pvCap.DeepCopy()
				vmt.persistentVolumeSize = &pvCapCopy
			}
		}
		dsw.volumesToMount[volumeName] = vmt
	} else {
		// volume exists
		if pluginSupportsSELinuxContextMount {
			if seLinuxFileLabel != vol.seLinuxFileLabel {
				// TODO: update the error message after tests, e.g. add at least the conflicting pod names.
				fullErr := fmt.Errorf("conflicting SELinux labels of volume %s: %q and %q", volumeSpec.Name(), vol.seLinuxFileLabel, seLinuxFileLabel)
				supported := util.VolumeSupportsSELinuxMount(volumeSpec)
				if err := handleSELinuxMetricError(fullErr, supported, seLinuxVolumeContextMismatchWarnings, seLinuxVolumeContextMismatchErrors); err != nil {
					return "", err
				}
			} else {
				if seLinuxFileLabel != "" {
					seLinuxVolumesAdmitted.Add(1.0)
				}
			}
		}
	}

	oldPodMount, ok := dsw.volumesToMount[volumeName].podsToMount[podName]
	mountRequestTime := time.Now()
	if ok && !volumePlugin.RequiresRemount(volumeSpec) { // 对于特殊的volume ,判断是否需要重新挂载
		mountRequestTime = oldPodMount.mountRequestTime
	}

	// 创建新的podToMount对象.如果它已经存在,则使用更新的值进行刷新（对于需要在pod更新时重新挂载的卷,如 Downward API卷,这是必需的）.
	dsw.volumesToMount[volumeName].podsToMount[podName] = podToMount{
		podName:             podName,
		pod:                 pod,
		volumeSpec:          volumeSpec,
		outerVolumeSpecName: outerVolumeSpecName,
		mountRequestTime:    mountRequestTime,
	}
	return volumeName, nil
}

func (dsw *desiredStateOfWorld) GetVolumesToMount() []VolumeToMount {
	dsw.RLock()
	defer dsw.RUnlock()

	volumesToMount := make([]VolumeToMount, 0 /* len */, len(dsw.volumesToMount) /* cap */)
	for volumeName, volumeObj := range dsw.volumesToMount {
		for podName, podObj := range volumeObj.podsToMount {
			vmt := VolumeToMount{
				VolumeToMount: operationexecutor.VolumeToMount{
					VolumeName:              volumeName,
					PodName:                 podName,
					Pod:                     podObj.pod,
					VolumeSpec:              podObj.volumeSpec,
					PluginIsAttachable:      volumeObj.pluginIsAttachable,
					PluginIsDeviceMountable: volumeObj.pluginIsDeviceMountable,
					OuterVolumeSpecName:     podObj.outerVolumeSpecName,
					VolumeGidValue:          volumeObj.volumeGidValue,
					ReportedInUse:           volumeObj.reportedInUse,
					MountRequestTime:        podObj.mountRequestTime,
					DesiredSizeLimit:        volumeObj.desiredSizeLimit,
					SELinuxLabel:            volumeObj.seLinuxFileLabel,
				},
			}
			if volumeObj.persistentVolumeSize != nil {
				vmt.PersistentVolumeSize = volumeObj.persistentVolumeSize.DeepCopy()
			}
			volumesToMount = append(volumesToMount, vmt)
		}
	}
	return volumesToMount
}
func (dsw *desiredStateOfWorld) DeletePodFromVolume(
	podName types.UniquePodName, volumeName v1.UniqueVolumeName) {
	dsw.Lock()
	defer dsw.Unlock()

	delete(dsw.podErrors, podName)

	volumeObj, volumeExists := dsw.volumesToMount[volumeName]
	if !volumeExists {
		return
	}

	if _, podExists := volumeObj.podsToMount[podName]; !podExists {
		return
	}

	// Delete pod if it exists
	delete(dsw.volumesToMount[volumeName].podsToMount, podName)

	if len(dsw.volumesToMount[volumeName].podsToMount) == 0 {
		// Delete volume if no child pods left
		delete(dsw.volumesToMount, volumeName)
	}
}
