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

package operationexecutor

import (
	"fmt"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	kevents "k8s.io/kubernetes/pkg/kubelet/events"
	"k8s.io/kubernetes/pkg/volume/util"
	volumetypes "k8s.io/kubernetes/pkg/volume/util/types"
)

type NodeExpander struct {
	resizeOpts        nodeResizeOperationOpts
	kubeClient        clientset.Interface
	recorder          record.EventRecorder
	pvcStatusCap      resource.Quantity
	pvCap             resource.Quantity
	resizeStatus      *v1.PersistentVolumeClaimResizeStatus
	pvcAlreadyUpdated bool // 如果为 true,则表示尽管我们在 kubelet 上调用了
}

// testResponseData 在单元测试中进行健全性检查.
type testResponseData struct {
	resizeCalledOnPlugin bool // 指示底层卷驱动程序上是否调用了调整操作,主要用于测试.
	// 指示 kubelet 是否应将调整操作视为完成.对于 kubelet,即使实际调整没有完成,也可以将调整操作视为完成.这可能是因为某些预检查失败,kubelet 不应重试扩展,或者可能是因为调整操作真正完成了.
	assumeResizeFinished bool
}

func (ne *NodeExpander) expandOnPlugin() (bool, error, testResponseData) {
	allowExpansion := ne.runPreCheck()
	if !allowExpansion {
		return false, nil, testResponseData{false, true}
	}

	var err error
	nodeName := ne.resizeOpts.vmt.Pod.Spec.NodeName

	if !ne.pvcAlreadyUpdated {
		ne.resizeOpts.pvc, err = util.MarkNodeExpansionInProgress(ne.resizeOpts.pvc, ne.kubeClient)

		if err != nil {
			msg := ne.resizeOpts.vmt.GenerateErrorDetailed("MountVolume.NodeExpandVolume failed to mark node expansion in progress: %v", err)
			klog.Errorf(msg.Error())
			return false, err, testResponseData{}
		}
	}
	_, resizeErr := ne.resizeOpts.volumePlugin.NodeExpand(ne.resizeOpts.pluginResizeOpts)
	if resizeErr != nil {
		if volumetypes.IsOperationFinishedError(resizeErr) {
			var markFailedError error
			ne.resizeOpts.pvc, markFailedError = util.MarkNodeExpansionFailed(ne.resizeOpts.pvc, ne.kubeClient)
			if markFailedError != nil {
				klog.Errorf(ne.resizeOpts.vmt.GenerateErrorDetailed("MountMount.NodeExpandVolume failed to mark node expansion as failed: %v", err).Error())
			}
		}

		// if driver returned FailedPrecondition error that means
		// volume expansion should not be retried on this node but
		// expansion operation should not block mounting
		if volumetypes.IsFailedPreconditionError(resizeErr) {
			ne.resizeOpts.actualStateOfWorld.MarkForInUseExpansionError(ne.resizeOpts.vmt.VolumeName)
			klog.Errorf(ne.resizeOpts.vmt.GenerateErrorDetailed("MountVolume.NodeExapndVolume failed with %v", resizeErr).Error())
			return false, nil, testResponseData{assumeResizeFinished: true, resizeCalledOnPlugin: true}
		}
		return false, resizeErr, testResponseData{assumeResizeFinished: true, resizeCalledOnPlugin: true}
	}
	simpleMsg, detailedMsg := ne.resizeOpts.vmt.GenerateMsg("MountVolume.NodeExpandVolume succeeded", nodeName)
	ne.recorder.Eventf(ne.resizeOpts.vmt.Pod, v1.EventTypeNormal, kevents.FileSystemResizeSuccess, simpleMsg)
	ne.recorder.Eventf(ne.resizeOpts.pvc, v1.EventTypeNormal, kevents.FileSystemResizeSuccess, simpleMsg)
	klog.InfoS(detailedMsg, "pod", klog.KObj(ne.resizeOpts.vmt.Pod))

	// no need to update PVC object if we already updated it
	if ne.pvcAlreadyUpdated {
		return true, nil, testResponseData{true, true}
	}

	// File system resize succeeded, now update the PVC's Capacity to match the PV's
	ne.resizeOpts.pvc, err = util.MarkFSResizeFinished(ne.resizeOpts.pvc, ne.resizeOpts.pluginResizeOpts.NewSize, ne.kubeClient) // ✅
	if err != nil {
		return true, fmt.Errorf("mountVolume.NodeExpandVolume update pvc status failed: %v", err), testResponseData{true, true}
	}
	return true, nil, testResponseData{true, true}
}

func newNodeExpander(resizeOp nodeResizeOperationOpts, client clientset.Interface, recorder record.EventRecorder) *NodeExpander {
	return &NodeExpander{
		kubeClient: client,
		resizeOpts: resizeOp,
		recorder:   recorder,
	}
}

// runPreCheck 在对 PVC 进行扩展之前,执行一些健全性检查.
func (ne *NodeExpander) runPreCheck() bool {
	ne.pvcStatusCap = ne.resizeOpts.pvc.Status.Capacity[v1.ResourceStorage]
	ne.pvCap = ne.resizeOpts.pv.Spec.Capacity[v1.ResourceStorage]

	ne.resizeStatus = ne.resizeOpts.pvc.Status.ResizeStatus
	// PVC 已经扩展,但是我们仍然尝试扩展卷,因为 ASOW 中的最后记录大小较旧.这可能会发生在 RWX 卷类型中.
	if ne.pvcStatusCap.Cmp(ne.resizeOpts.pluginResizeOpts.NewSize) >= 0 && (ne.resizeStatus == nil || *ne.resizeStatus == v1.PersistentVolumeClaimNoExpansionInProgress) {
		ne.pvcAlreadyUpdated = true
	}

	// if resizestatus is nil or NodeExpansionInProgress or NodeExpansionPending then we
	// should allow volume expansion on the node to proceed. We are making an exception for
	// resizeStatus being nil because it will support use cases where
	// resizeStatus may not be set (old control-plane expansion controller etc).
	if ne.resizeStatus == nil ||
		ne.pvcAlreadyUpdated ||
		*ne.resizeStatus == v1.PersistentVolumeClaimNodeExpansionPending ||
		*ne.resizeStatus == v1.PersistentVolumeClaimNodeExpansionInProgress {
		return true
	}

	return false
}
