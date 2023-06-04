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
Package populator implements interfaces that monitor and keep the states of the
caches in sync with the "ground truth".
实现了监控和保持缓存状态与“基本事实”同步的接口.
*/
package populator

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"k8s.io/klog/v2"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/component-helpers/storage/ephemeral"
	"k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/pkg/kubelet/config"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/pod"
	"k8s.io/kubernetes/pkg/kubelet/volumemanager/cache"
	"k8s.io/kubernetes/pkg/volume"
	"k8s.io/kubernetes/pkg/volume/csimigration"
	"k8s.io/kubernetes/pkg/volume/util"
	volumetypes "k8s.io/kubernetes/pkg/volume/util/types"
)

// DesiredStateOfWorldPopulator periodically loops through the list of active
// pods and ensures that each one exists in the desired state of the world cache
// if it has volumes. It also verifies that the pods in the desired state of the
// world cache still exist, if not, it removes them.
type DesiredStateOfWorldPopulator interface {
	Run(sourcesReady config.SourcesReady, stopCh <-chan struct{}) // 从 apiserver 同步到的pod信息,来更新DesiredStateOfWorld
	// ReprocessPod 将 processsedpods 中指定pod的值设置为false,强制对其进行重新处理.这是启用在pod更新上重新挂载卷所必需的(像向下API卷这样的卷依赖于此行为来确保卷内容更新).
	ReprocessPod(podName volumetypes.UniquePodName)
	// HasAddedPods 返回populator是否循环遍历了活动Pod列表并将它们至少添加到期望状态的世界缓存中一次,在所有源都准备好之后.
	// 在所有源都准备好之前,它不会返回true,因为在那之前,许多或所有Pod可能都不在活动Pod列表中,因此可能添加了很少或没有Pod.
	HasAddedPods() bool
}

type podStateProvider interface {
	ShouldPodContainersBeTerminating(types.UID) bool // 判断Pod中的容器是否应该被终止
	ShouldPodRuntimeBeRemoved(types.UID) bool        // 判断Pod的运行时是否应该被移除.
}

// NewDesiredStateOfWorldPopulator
// kubeClient -用于从API服务器获取PV和PVC对象
// loopSleepDuration -填充器循环休眠的时间
// podManager - kubelet podManager,它是此主机上存在的pod的真实来源
// desiredStateOfWorld - 填充缓存
func NewDesiredStateOfWorldPopulator(
	kubeClient clientset.Interface,
	loopSleepDuration time.Duration,
	getPodStatusRetryDuration time.Duration,
	podManager pod.Manager,
	podStateProvider podStateProvider,
	desiredStateOfWorld cache.DesiredStateOfWorld,
	actualStateOfWorld cache.ActualStateOfWorld,
	kubeContainerRuntime kubecontainer.Runtime,
	keepTerminatedPodVolumes bool,
	csiMigratedPluginManager csimigration.PluginManager,
	intreeToCSITranslator csimigration.InTreeToCSITranslator,
	volumePluginMgr *volume.VolumePluginMgr) DesiredStateOfWorldPopulator {
	return &desiredStateOfWorldPopulator{
		kubeClient:                kubeClient,
		loopSleepDuration:         loopSleepDuration,
		getPodStatusRetryDuration: getPodStatusRetryDuration,
		podManager:                podManager,
		podStateProvider:          podStateProvider,
		desiredStateOfWorld:       desiredStateOfWorld,
		actualStateOfWorld:        actualStateOfWorld,
		pods:                      processedPods{processedPods: make(map[volumetypes.UniquePodName]bool)},
		kubeContainerRuntime:      kubeContainerRuntime,
		keepTerminatedPodVolumes:  keepTerminatedPodVolumes,
		hasAddedPods:              false,
		hasAddedPodsLock:          sync.RWMutex{},
		csiMigratedPluginManager:  csiMigratedPluginManager,
		intreeToCSITranslator:     intreeToCSITranslator,
		volumePluginMgr:           volumePluginMgr,
	}
}

type desiredStateOfWorldPopulator struct {
	kubeClient                clientset.Interface
	loopSleepDuration         time.Duration                      // 循环休眠时间,表示每次循环之间的等待时间.
	getPodStatusRetryDuration time.Duration                      // 获取 Pod 状态的重试时间.
	podManager                pod.Manager                        // Pod 管理器,用于管理 Pod 的创建、删除等操作.
	podStateProvider          podStateProvider                   // Pod 状态提供器,用于获取 Pod 的状态信息.
	desiredStateOfWorld       cache.DesiredStateOfWorld          // 期望的世界状态,即应用程序所需的状态.
	actualStateOfWorld        cache.ActualStateOfWorld           // 实际的世界状态,即当前系统的状态.
	pods                      processedPods                      // 已处理的 Pod 列表.
	kubeContainerRuntime      kubecontainer.Runtime              //
	timeOfLastGetPodStatus    time.Time                          // 上次获取 Pod 状态的时间.
	keepTerminatedPodVolumes  bool                               // 是否保留已终止的 Pod 的卷.
	hasAddedPods              bool                               // 是否已添加 Pod.
	hasAddedPodsLock          sync.RWMutex                       //
	csiMigratedPluginManager  csimigration.PluginManager         //
	intreeToCSITranslator     csimigration.InTreeToCSITranslator // InTree 到 CSI 的翻译器.
	volumePluginMgr           *volume.VolumePluginMgr            //
}

type processedPods struct {
	processedPods map[volumetypes.UniquePodName]bool
	sync.RWMutex
}

// 同步从 apiserver 拿到的pod信息,来更新DesiredStateOfWorld
func (dswp *desiredStateOfWorldPopulator) populatorLoop() {
	dswp.findAndAddNewPods()

	// findAndRemoveDeletedPods() 函数会调用容器运行时来确定给定 Pod 的容器是否已终止.
	// 这是一个昂贵的操作,因此我们独立于主 populator 循环限制 findAndRemoveDeletedPods() 的调用速率.也就是说,为了减轻系统负担,我们对这个函数的调用频率进行了限制.
	if time.Since(dswp.timeOfLastGetPodStatus) < dswp.getPodStatusRetryDuration {
		klog.V(5).InfoS("Skipping findAndRemoveDeletedPods(). ", "nextRetryTime", dswp.timeOfLastGetPodStatus.Add(dswp.getPodStatusRetryDuration), "retryDuration", dswp.getPodStatusRetryDuration)
		return
	}

	dswp.findAndRemoveDeletedPods()
}

// 调用容器运行时来确定给定Pod的容器是否已终止.
func (dswp *desiredStateOfWorldPopulator) findAndRemoveDeletedPods() {
	for _, volumeToMount := range dswp.desiredStateOfWorld.GetVolumesToMount() {
		// 根据volumeToMount.Pod判断该Volume所属的Pod是否存在于podManager
		pod, podExists := dswp.podManager.GetPodByUID(volumeToMount.Pod.UID)
		if podExists { // 如果存在podExists,则继续判断pod是否终止：如果pod为终止则忽略
			// check if the attachability has changed for this volume
			if volumeToMount.PluginIsAttachable {
				attachableVolumePlugin, err := dswp.volumePluginMgr.FindAttachablePluginBySpec(volumeToMount.VolumeSpec)
				// only this means the plugin is truly non-attachable
				if err == nil && attachableVolumePlugin == nil {
					// It is not possible right now for a CSI plugin to be both attachable and non-deviceMountable
					// So the uniqueVolumeName should remain the same after the attachability change
					dswp.desiredStateOfWorld.MarkVolumeAttachability(volumeToMount.VolumeName, false)
					klog.InfoS("Volume changes from attachable to non-attachable", "volumeName", volumeToMount.VolumeName)
					continue
				}
			}

			// 排除我们期望正在运行的已知Pod.
			if !dswp.podStateProvider.ShouldPodRuntimeBeRemoved(pod.UID) {
				continue
			}
			if dswp.keepTerminatedPodVolumes {
				continue
			}
		}

		// Once a pod has been deleted from kubelet pod manager, do not delete
		// it immediately from volume manager. Instead, check the kubelet
		// pod state provider to verify that all containers in the pod have been
		// terminated.
		// 根据containerRuntime进一步判断pod中的全部容器是否终止：如果该pod仍有容器未终止,则忽略
		if !dswp.podStateProvider.ShouldPodRuntimeBeRemoved(volumeToMount.Pod.UID) {
			klog.V(4).InfoS("Pod still has one or more containers in the non-exited state and will not be removed from desired state", "pod", klog.KObj(volumeToMount.Pod))
			continue
		}
		//根据actualStateOfWorld.PodExistsInVolume判断：Actual state没有该pod的挂载volume,但pod manager仍有该pod,则忽略
		var volumeToMountSpecName string
		if volumeToMount.VolumeSpec != nil {
			volumeToMountSpecName = volumeToMount.VolumeSpec.Name()
		}
		removed := dswp.actualStateOfWorld.PodRemovedFromVolume(volumeToMount.PodName, volumeToMount.VolumeName)
		if removed && podExists {
			klog.V(4).InfoS("Actual state does not yet have volume mount information and pod still exists in pod manager, skip removing volume from desired state", "pod", klog.KObj(volumeToMount.Pod), "podUID", volumeToMount.Pod.UID, "volumeName", volumeToMountSpecName)
			continue
		}
		// 删除管理器中该pod的该挂载卷并删除管理器中该pod信息
		klog.V(4).InfoS("Removing volume from desired state", "pod", klog.KObj(volumeToMount.Pod), "podUID", volumeToMount.Pod.UID, "volumeName", volumeToMountSpecName)
		dswp.desiredStateOfWorld.DeletePodFromVolume(volumeToMount.PodName, volumeToMount.VolumeName)
		dswp.deleteProcessedPod(volumeToMount.PodName)

	}
	//- 这是理想的volume状态,这里并没有发生实际的volume的创建删除挂载卸载操作
	//- 实际的操作由reconciler.Run完成
	podsWithError := dswp.desiredStateOfWorld.GetPodsWithErrors()
	for _, podName := range podsWithError {
		if _, podExists := dswp.podManager.GetPodByUID(types.UID(podName)); !podExists {
			dswp.desiredStateOfWorld.PopPodErrors(podName)
		}
	}
}

// markPodProcessingFailed marks the specified pod from processedPods as false to indicate that it failed processing
func (dswp *desiredStateOfWorldPopulator) markPodProcessingFailed(
	podName volumetypes.UniquePodName) {
	dswp.pods.Lock()
	// 的Pod标记为未处理,即失败处理.当某个Pod处理失败时,可以通过调用该函数将其标记为未处理,以便后续重新处理.
	dswp.pods.processedPods[podName] = false
	dswp.pods.Unlock()
}

func (dswp *desiredStateOfWorldPopulator) ReprocessPod(podName volumetypes.UniquePodName) {
	// 用于重新处理一个Pod.Pod是Kubernetes中最小的可部署对象,它由一个或多个容器组成,共享网络和存储资源.
	// 当Pod中的容器发生故障或需要更新时,可以使用ReprocessPod命令重新处理Pod.这将导致Pod中的所有容器被终止并重新启动.
	// 重新启动后,Pod将使用最新的容器镜像或配置文件.ReprocessPod 可以确保Pod中的容器始终处于最新状态,并确保应用程序的稳定性和可靠性.
	dswp.markPodProcessingFailed(podName)
}

// Run 同步从 apiserver 拿到的pod信息,来更新DesiredStateOfWorld
func (dswp *desiredStateOfWorldPopulator) Run(sourcesReady config.SourcesReady, stopCh <-chan struct{}) {
	//go vm.desiredStateOfWorldPopulator.Run(sourcesReady, stopCh)

	// Wait for the completion of a loop that started after sources are all ready, then set hasAddedPods accordingly
	klog.InfoS("Desired state populator starts to run")
	wait.PollUntil(dswp.loopSleepDuration, func() (bool, error) {
		done := sourcesReady.AllReady()
		dswp.populatorLoop()
		return done, nil
	}, stopCh)
	dswp.hasAddedPodsLock.Lock()
	if !dswp.hasAddedPods {
		klog.InfoS("Finished populating initial desired state of world")
		dswp.hasAddedPods = true
	}
	dswp.hasAddedPodsLock.Unlock()
	wait.Until(dswp.populatorLoop, dswp.loopSleepDuration, stopCh)
}

func (dswp *desiredStateOfWorldPopulator) HasAddedPods() bool {
	dswp.hasAddedPodsLock.RLock()
	defer dswp.hasAddedPodsLock.RUnlock()
	return dswp.hasAddedPods
}

// 遍历所有的 Pod,如果它们不存在但应该存在,则将它们添加到期望的世界状态中.
// 这段代码的作用是检查系统中是否有缺失的 Pod,如果有则添加到期望的状态中,以确保系统中所有应该存在的 Pod 都已经被创建.
func (dswp *desiredStateOfWorldPopulator) findAndAddNewPods() {
	// Map unique pod name to outer volume name to MountedVolume.
	// 所有pod的mount状态
	mountedVolumesForPod := make(map[volumetypes.UniquePodName]map[string]cache.MountedVolume)
	for _, mountedVolume := range dswp.actualStateOfWorld.GetMountedVolumes() { // 当前
		mountedVolumes, exist := mountedVolumesForPod[mountedVolume.PodName]
		if !exist {
			mountedVolumes = make(map[string]cache.MountedVolume)
			mountedVolumesForPod[mountedVolume.PodName] = mountedVolumes
		}
		mountedVolumes[mountedVolume.OuterVolumeSpecName] = mountedVolume
	}

	for _, pod := range dswp.podManager.GetPods() {
		// Keep consistency of adding pod during reconstruction
		if dswp.hasAddedPods && dswp.podStateProvider.ShouldPodContainersBeTerminating(pod.UID) { // 判断Pod中的容器是否应该被终止
			// Do not (re)add volumes for pods that can't also be starting containers
			continue
		}

		if !dswp.hasAddedPods && dswp.podStateProvider.ShouldPodRuntimeBeRemoved(pod.UID) { // 判断Pod的运行时是否应该被移除.
			// When kubelet restarts, we need to add pods to dsw if there is a possibility
			// that the container may still be running
			//
			continue
		}

		dswp.processPodVolumes(pod, mountedVolumesForPod)
	}
}

// 如果 populator 已经处理/重新处理过此 Pod 的卷,则 podPreviouslyProcessed 函数返回 true.否则,需要重新处理此 Pod 的卷.
func (dswp *desiredStateOfWorldPopulator) podPreviouslyProcessed(podName volumetypes.UniquePodName) bool {
	dswp.pods.RLock()
	defer dswp.pods.RUnlock()
	return dswp.pods.processedPods[podName]
}

func (dswp *desiredStateOfWorldPopulator) podHasBeenSeenOnce(podName volumetypes.UniquePodName) bool {
	dswp.pods.RLock()
	_, exist := dswp.pods.processedPods[podName]
	dswp.pods.RUnlock()
	return exist
}

// markPodProcessed records that the volumes for the specified pod have been
// processed by the populator
func (dswp *desiredStateOfWorldPopulator) markPodProcessed(podName volumetypes.UniquePodName) {
	dswp.pods.Lock()
	defer dswp.pods.Unlock()
	dswp.pods.processedPods[podName] = true
}

// deleteProcessedPod removes the specified pod from processedPods
func (dswp *desiredStateOfWorldPopulator) deleteProcessedPod(podName volumetypes.UniquePodName) {
	dswp.pods.Lock()
	defer dswp.pods.Unlock()
	delete(dswp.pods.processedPods, podName)
}

// 函数从API服务器获取给定命名空间和名称的PVC对象,检查PVC是否正在被删除,
// 提取它指向的PV的名称并返回它.如果PVC对象的阶段不是“Bound”,则返回错误.
func (dswp *desiredStateOfWorldPopulator) getPVCExtractPV(namespace string, claimName string) (*v1.PersistentVolumeClaim, error) {
	pvc, err :=
		dswp.kubeClient.CoreV1().PersistentVolumeClaims(namespace).Get(context.TODO(), claimName, metav1.GetOptions{})
	if err != nil || pvc == nil {
		return nil, fmt.Errorf("failed to fetch PVC from API server: %v", err)
	}
	//使用正在被删除的PVC的Pod必须不被启动.
	if pvc.ObjectMeta.DeletionTimestamp != nil {
		return nil, errors.New("PVC is being deleted")
	}

	if pvc.Status.Phase != v1.ClaimBound {
		return nil, errors.New("PVC is not bound")
	}
	if pvc.Spec.VolumeName == "" {
		return nil, errors.New("PVC has empty pvc.Spec.VolumeName")
	}

	return pvc, nil
}

// 这段代码的作用是从API服务器中获取给定名称的PV对象,并将其表示为volume.Spec.
// 如果获取PV对象的过程中出现错误,则会返回一个错误.在Kubernetes中,PV（Persistent Volume）是一种持久化存储资源,
// 用于保留应用程序的数据,因此获取PV对象通常是为了在应用程序中使用它来进行持久化存储.
func (dswp *desiredStateOfWorldPopulator) getPVSpec(name string, pvcReadOnly bool, expectedClaimUID types.UID) (*volume.Spec, string, error) {
	pv, err := dswp.kubeClient.CoreV1().PersistentVolumes().Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil || pv == nil {
		return nil, "", fmt.Errorf(
			"failed to fetch PV %s from API server: %v", name, err)
	}

	if pv.Spec.ClaimRef == nil {
		return nil, "", fmt.Errorf(
			"found PV object %s but it has a nil pv.Spec.ClaimRef indicating it is not yet bound to the claim",
			name)
	}

	if pv.Spec.ClaimRef.UID != expectedClaimUID {
		return nil, "", fmt.Errorf(
			"found PV object %s but its pv.Spec.ClaimRef.UID %s does not point to claim.UID %s",
			name,
			pv.Spec.ClaimRef.UID,
			expectedClaimUID)
	}

	volumeGidValue := getPVVolumeGidAnnotationValue(pv)
	return volume.NewSpecFromPersistentVolume(pv, pvcReadOnly), volumeGidValue, nil
}

func getPVVolumeGidAnnotationValue(pv *v1.PersistentVolume) string {
	if volumeGid, ok := pv.Annotations[util.VolumeGidAnnotationKey]; ok {
		return volumeGid
	}

	return ""
}

// 为指定的卷创建并返回可变的 volume.Spec 对象.如果需要,它会取消引用任何 PVC 以获取 PV 对象.如果无法立即获取卷,则返回错误.
func (dswp *desiredStateOfWorldPopulator) createVolumeSpec(
	podVolume v1.Volume, pod *v1.Pod, mounts, devices sets.String,
) (*v1.PersistentVolumeClaim, *volume.Spec, string, error) {
	pvcSource := podVolume.VolumeSource.PersistentVolumeClaim
	isEphemeral := pvcSource == nil && podVolume.VolumeSource.Ephemeral != nil // 是不是需要动态创建PVC
	if isEphemeral {
		// 通用的临时内联卷和 PVC 引用的处理方式相同.唯一的额外限制（在下面进行检查）是 PVC 必须归属于该 Pod.
		pvcSource = &v1.PersistentVolumeClaimVolumeSource{
			ClaimName: ephemeral.VolumeClaimName(pod, &podVolume),
		}
	}
	if pvcSource != nil {
		klog.V(5).InfoS("Found PVC", "PVC", klog.KRef(pod.Namespace, pvcSource.ClaimName))
		// 获取一个已存在的PVC
		pvc, err := dswp.getPVCExtractPV(pod.Namespace, pvcSource.ClaimName)
		if err != nil {
			return nil, nil, "", fmt.Errorf("error processing PVC %s/%s: %v", pod.Namespace, pvcSource.ClaimName, err)
		}
		if isEphemeral {
			if err := ephemeral.VolumeIsForPod(pod, pvc); err != nil {
				return nil, nil, "", err
			}
		}
		pvName, pvcUID := pvc.Spec.VolumeName, pvc.UID
		klog.V(5).InfoS("Found bound PV for PVC", "PVC", klog.KRef(pod.Namespace, pvcSource.ClaimName), "PVCUID", pvcUID, "PVName", pvName)
		// 获取实际的PV对象
		volumeSpec, volumeGidValue, err := dswp.getPVSpec(pvName, pvcSource.ReadOnly, pvcUID)
		if err != nil {
			return nil, nil, "", fmt.Errorf(
				"error processing PVC %s/%s: %v",
				pod.Namespace,
				pvcSource.ClaimName,
				err)
		}
		klog.V(5).InfoS("Extracted volumeSpec from bound PV and PVC", "PVC", klog.KRef(pod.Namespace, pvcSource.ClaimName), "PVCUID", pvcUID, "PVName", pvName, "volumeSpecName", volumeSpec.Name())
		migratable, err := dswp.csiMigratedPluginManager.IsMigratable(volumeSpec)
		// CSI迁移则是指将旧的存储插件接口迁移到CSI接口的过程
		if err != nil {
			return nil, nil, "", err
		}
		if migratable {
			volumeSpec, err = csimigration.TranslateInTreeSpecToCSI(volumeSpec, pod.Namespace, dswp.intreeToCSITranslator)
			if err != nil {
				return nil, nil, "", err
			}
		}

		// TODO: replace this with util.GetVolumeMode() when features.BlockVolume is removed.
		// The function will return the right value then.
		volumeMode := v1.PersistentVolumeFilesystem
		if volumeSpec.PersistentVolume != nil && volumeSpec.PersistentVolume.Spec.VolumeMode != nil {
			volumeMode = *volumeSpec.PersistentVolume.Spec.VolumeMode
		}

		// TODO: remove features.BlockVolume checks / comments after no longer needed
		// Error if a container has volumeMounts but the volumeMode of PVC isn't Filesystem.
		// Do not check feature gate here to make sure even when the feature is disabled in kubelet,
		// because controller-manager / API server can already contain block PVs / PVCs.
		if mounts.Has(podVolume.Name) && volumeMode != v1.PersistentVolumeFilesystem {
			return nil, nil, "", fmt.Errorf(
				"volume %s has volumeMode %s, but is specified in volumeMounts",
				podVolume.Name,
				volumeMode)
		}
		// Error if a container has volumeDevices but the volumeMode of PVC isn't Block
		if devices.Has(podVolume.Name) && volumeMode != v1.PersistentVolumeBlock {
			return nil, nil, "", fmt.Errorf(
				"volume %s has volumeMode %s, but is specified in volumeDevices",
				podVolume.Name,
				volumeMode)
		}
		return pvc, volumeSpec, volumeGidValue, nil
	}
	// 没有s
	// Do not return the original volume object, since the source could mutate it
	clonedPodVolume := podVolume.DeepCopy()

	spec := volume.NewSpecFromVolume(clonedPodVolume)
	migratable, err := dswp.csiMigratedPluginManager.IsMigratable(spec)
	if err != nil {
		return nil, nil, "", err
	}
	if migratable {
		spec, err = csimigration.TranslateInTreeSpecToCSI(spec, pod.Namespace, dswp.intreeToCSITranslator)
		if err != nil {
			return nil, nil, "", err
		}
	}
	return nil, spec, "", nil
}

func getUniqueVolumeName(
	podName volumetypes.UniquePodName,
	outerVolumeSpecName string,
	mountedVolumesForPod map[volumetypes.UniquePodName]map[string]cache.MountedVolume) (v1.UniqueVolumeName, bool) {
	mountedVolumes, exist := mountedVolumesForPod[podName]
	if !exist {
		return "", false
	}
	mountedVolume, exist := mountedVolumes[outerVolumeSpecName]
	if !exist {
		return "", false
	}
	return mountedVolume.VolumeName, true
}

// checkVolumeFSResize 记录由pod挂载的卷的期望PVC大小.它用于与实际大小（来自pvc.Status.Capacity）进行比较,并在需要时在节点上调用卷扩展.
func (dswp *desiredStateOfWorldPopulator) checkVolumeFSResize(
	pod *v1.Pod,
	podVolume v1.Volume,
	pvc *v1.PersistentVolumeClaim,
	volumeSpec *volume.Spec,
	uniquePodName volumetypes.UniquePodName,
	mountedVolumesForPod map[volumetypes.UniquePodName]map[string]cache.MountedVolume,
) {

	// if a volumeSpec does not have PV or has InlineVolumeSpecForCSIMigration set or pvc is nil
	// we can't resize the volume and hence resizing should be skipped.
	if volumeSpec.PersistentVolume == nil || volumeSpec.InlineVolumeSpecForCSIMigration || pvc == nil {
		// Only PVC supports resize operation.
		return
	}

	uniqueVolumeName, exist := getUniqueVolumeName(uniquePodName, podVolume.Name, mountedVolumesForPod)
	if !exist {
		// Volume not exist in ASW, we assume it hasn't been mounted yet. If it needs resize,
		// it will be handled as offline resize(if it indeed hasn't been mounted yet),
		// or online resize in subsequent loop(after we confirm it has been mounted).
		return
	}
	// volumeSpec.ReadOnly is the value that determines if volume could be formatted when being mounted.
	// This is the same flag that determines filesystem resizing behaviour for offline resizing and hence
	// we should use it here. This value comes from Pod.spec.volumes.persistentVolumeClaim.readOnly.
	if volumeSpec.ReadOnly {
		// This volume is used as read only by this pod, we don't perform resize for read only volumes.
		klog.V(5).InfoS("Skip file system resize check for the volume, as the volume is mounted as readonly", "pod", klog.KObj(pod), "volumeName", podVolume.Name)
		return
	}
	pvCap := volumeSpec.PersistentVolume.Spec.Capacity.Storage()
	pvcStatusCap := pvc.Status.Capacity.Storage()
	dswp.desiredStateOfWorld.UpdatePersistentVolumeSize(uniqueVolumeName, pvCap)

	// in case the actualStateOfWorld was rebuild after kubelet restart ensure that claimSize is set to accurate value
	dswp.actualStateOfWorld.InitializeClaimSize(uniqueVolumeName, pvcStatusCap)
}

// 处理给定 Pod 中的卷,并将它们添加到期望的世界状态中.
func (dswp *desiredStateOfWorldPopulator) processPodVolumes(
	pod *v1.Pod,
	mountedVolumesForPod map[volumetypes.UniquePodName]map[string]cache.MountedVolume,
) {
	if pod == nil {
		return
	}

	uniquePodName := util.GetUniquePodName(pod)
	if dswp.podPreviouslyProcessed(uniquePodName) {
		return
	}

	allVolumesAdded := true
	mounts, devices, seLinuxContainerContexts := util.GetPodVolumeNames(pod)

	// Process volume spec for each volume defined in pod
	for _, podVolume := range pod.Spec.Volumes { // 可能volume 声明了,但并没有被实际使用
		if !mounts.Has(podVolume.Name) && !devices.Has(podVolume.Name) {
			// Volume is not used in the pod, ignore it.
			klog.V(4).InfoS("Skipping unused volume", "pod", klog.KObj(pod), "volumeName", podVolume.Name)
			continue
		}
		// 遍历pod的volume配置,调用createVolumeSpec获取卷的spec对象
		pvc, volumeSpec, volumeGidValue, err := dswp.createVolumeSpec(podVolume, pod, mounts, devices)
		if err != nil {
			klog.ErrorS(err, "Error processing volume", "pod", klog.KObj(pod), "volumeName", podVolume.Name)
			dswp.desiredStateOfWorld.AddErrorToPod(uniquePodName, err.Error())
			allVolumesAdded = false
			continue
		}

		// 更新desiredStateOfWorld,在缓存中更新,意思是指定的pod需要挂载执行的volume
		uniqueVolumeName, err := dswp.desiredStateOfWorld.AddPodToVolume(
			uniquePodName, pod, volumeSpec, podVolume.Name, volumeGidValue, seLinuxContainerContexts[podVolume.Name],
		)
		if err != nil {
			klog.ErrorS(err, "Failed to add volume to desiredStateOfWorld", "pod", klog.KObj(pod), "volumeName", podVolume.Name, "volumeSpecName", volumeSpec.Name())
			dswp.desiredStateOfWorld.AddErrorToPod(uniquePodName, err.Error())
			allVolumesAdded = false
		} else {
			klog.V(4).InfoS("Added volume to desired state", "pod", klog.KObj(pod), "volumeName", podVolume.Name, "volumeSpecName", volumeSpec.Name())
		}
		if !utilfeature.DefaultFeatureGate.Enabled(features.SELinuxMountReadWriteOncePod) {
			// sync reconstructed volume. This is necessary only when the old-style reconstruction is still used.
			// With reconstruct_new.go, AWS.MarkVolumeAsMounted will update the outer spec name of previously
			// uncertain volumes.
			dswp.actualStateOfWorld.SyncReconstructedVolume(uniqueVolumeName, uniquePodName, podVolume.Name)
		}

		dswp.checkVolumeFSResize(pod, podVolume, pvc, volumeSpec, uniquePodName, mountedVolumesForPod)
	}

	// 某些卷的添加可能失败了,不应将此pod标记为已完全处理.
	if allVolumesAdded {
		dswp.markPodProcessed(uniquePodName)
		// 新的pod已同步.重新挂载所有需要它的卷（例如DownwardAPI卷）.
		dswp.actualStateOfWorld.MarkRemountRequired(uniquePodName)
		// 删除存储的与此pod相关的任何错误,此processPodVolumes过程中一切顺利.
		dswp.desiredStateOfWorld.PopPodErrors(uniquePodName)
	} else if dswp.podHasBeenSeenOnce(uniquePodName) {
		//对于已至少处理一次的Pod,即使本轮中某些卷未能成功重新处理,我们仍将其标记为已处理,
		//以避免以非常高的频率处理它.当卷管理器调用ReprocessPod()时,将重新处理Pod,该方法由SyncPod触发.
		dswp.markPodProcessed(uniquePodName)
	}

}
