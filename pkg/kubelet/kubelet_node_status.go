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

package kubelet

import (
	"context"
	"fmt"
	"net"
	goruntime "runtime"
	"sort"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	cloudprovider "k8s.io/cloud-provider"
	cloudproviderapi "k8s.io/cloud-provider/api"
	nodeutil "k8s.io/component-helpers/node/util"
	"k8s.io/klog/v2"
	kubeletapis "k8s.io/kubelet/pkg/apis"
	v1helper "k8s.io/kubernetes/pkg/apis/core/v1/helper"
	"k8s.io/kubernetes/pkg/kubelet/events"
	"k8s.io/kubernetes/pkg/kubelet/nodestatus"
	"k8s.io/kubernetes/pkg/kubelet/util"
	taintutil "k8s.io/kubernetes/pkg/util/taints"
	volutil "k8s.io/kubernetes/pkg/volume/util"
)

// ✅
func (kl *Kubelet) registerWithAPIServer() { // ✅
	if kl.registrationCompleted {
		return
	}
	step := 100 * time.Millisecond

	for {
		time.Sleep(step)
		step = step * 2
		if step >= 7*time.Second {
			step = 7 * time.Second
		}

		node, err := kl.initialNode(context.TODO())
		if err != nil {
			klog.ErrorS(err, "Unable to construct v1.Node object for kubelet")
			continue
		}

		klog.InfoS("Attempting to register node", "node", klog.KObj(node))
		registered := kl.tryRegisterWithAPIServer(node)
		if registered {
			klog.InfoS("Successfully registered node", "node", klog.KObj(node))
			kl.registrationCompleted = true
			return
		}
	}
}

// ✅
func (kl *Kubelet) tryRegisterWithAPIServer(node *v1.Node) bool {
	_, err := kl.kubeClient.CoreV1().Nodes().Create(context.TODO(), node, metav1.CreateOptions{})
	if err == nil {
		return true
	}

	if !apierrors.IsAlreadyExists(err) {
		klog.ErrorS(err, "Unable to register node with API server", "node", klog.KObj(node))
		return false
	}

	existingNode, err := kl.kubeClient.CoreV1().Nodes().Get(context.TODO(), string(kl.nodeName), metav1.GetOptions{})
	if err != nil {
		klog.ErrorS(err, "Unable to register node with API server, error getting existing node", "node", klog.KObj(node))
		return false
	}
	if existingNode == nil {
		klog.InfoS("Unable to register node with API server, no node instance returned", "node", klog.KObj(node))
		return false
	}

	originalNode := existingNode.DeepCopy()

	klog.InfoS("Node was previously registered", "node", klog.KObj(node))

	// Edge case: the node was previously registered; reconcile
	// the value of the controller-managed attach-detach
	// annotation.
	requiresUpdate := kl.reconcileCMADAnnotationWithExistingNode(node, existingNode)    // ✅
	requiresUpdate = kl.updateDefaultLabels(node, existingNode) || requiresUpdate       // ✅
	requiresUpdate = kl.reconcileExtendedResource(node, existingNode) || requiresUpdate // ✅
	requiresUpdate = kl.reconcileHugePageResource(node, existingNode) || requiresUpdate // ✅
	if requiresUpdate {
		if _, _, err := nodeutil.PatchNodeStatus( // ✅
			kl.kubeClient.CoreV1(),
			types.NodeName(kl.nodeName),
			originalNode,
			existingNode,
		); err != nil {
			klog.ErrorS(err, "Unable to reconcile node with API server,error updating node", "node", klog.KObj(node))
			return false
		}
	}

	return true
}

func (kl *Kubelet) reconcileHugePageResource(initialNode, existingNode *v1.Node) bool { // ✅
	requiresUpdate := updateDefaultResources(initialNode, existingNode)
	supportedHugePageResources := sets.String{}

	for resourceName := range initialNode.Status.Capacity {
		if !v1helper.IsHugePageResourceName(resourceName) {
			continue
		}
		supportedHugePageResources.Insert(string(resourceName))

		initialCapacity := initialNode.Status.Capacity[resourceName]
		initialAllocatable := initialNode.Status.Allocatable[resourceName]

		capacity, resourceIsSupported := existingNode.Status.Capacity[resourceName]
		allocatable := existingNode.Status.Allocatable[resourceName]

		// Add or update capacity if it the size was previously unsupported or has changed
		if !resourceIsSupported || capacity.Cmp(initialCapacity) != 0 {
			existingNode.Status.Capacity[resourceName] = initialCapacity.DeepCopy()
			requiresUpdate = true
		}

		// Add or update allocatable if it the size was previously unsupported or has changed
		if !resourceIsSupported || allocatable.Cmp(initialAllocatable) != 0 {
			existingNode.Status.Allocatable[resourceName] = initialAllocatable.DeepCopy()
			requiresUpdate = true
		}

	}

	for resourceName := range existingNode.Status.Capacity {
		if !v1helper.IsHugePageResourceName(resourceName) {
			continue
		}

		// If huge page size no longer is supported, we remove it from the node
		if !supportedHugePageResources.Has(string(resourceName)) {
			delete(existingNode.Status.Capacity, resourceName)
			delete(existingNode.Status.Allocatable, resourceName)
			klog.InfoS("移除不再支持的大页资源", "resourceName", resourceName)
			requiresUpdate = true
		}
	}
	return requiresUpdate
}

func (kl *Kubelet) reconcileExtendedResource(initialNode, node *v1.Node) bool { // ✅
	requiresUpdate := updateDefaultResources(initialNode, node)
	// Check with the device manager to see if node has been recreated, in which case extended resources should be zeroed until they are available
	if kl.containerManager.ShouldResetExtendedResourceCapacity() {
		for k := range node.Status.Capacity {
			if v1helper.IsExtendedResourceName(k) {
				klog.InfoS("将现有节点中的资源容量归零", "resourceName", k, "node", klog.KObj(node))
				node.Status.Capacity[k] = *resource.NewQuantity(int64(0), resource.DecimalSI)
				node.Status.Allocatable[k] = *resource.NewQuantity(int64(0), resource.DecimalSI)
				requiresUpdate = true
			}
		}
	}
	return requiresUpdate
}

func updateDefaultResources(initialNode, existingNode *v1.Node) bool { // ✅
	requiresUpdate := false
	if existingNode.Status.Capacity == nil {
		if initialNode.Status.Capacity != nil {
			existingNode.Status.Capacity = initialNode.Status.Capacity.DeepCopy()
			requiresUpdate = true
		} else {
			existingNode.Status.Capacity = make(map[v1.ResourceName]resource.Quantity)
		}
	}

	if existingNode.Status.Allocatable == nil {
		if initialNode.Status.Allocatable != nil {
			existingNode.Status.Allocatable = initialNode.Status.Allocatable.DeepCopy()
			requiresUpdate = true
		} else {
			existingNode.Status.Allocatable = make(map[v1.ResourceName]resource.Quantity)
		}
	}
	return requiresUpdate
}

// ✅
func (kl *Kubelet) updateDefaultLabels(initialNode, existingNode *v1.Node) bool {
	defaultLabels := []string{
		v1.LabelHostname,
		v1.LabelTopologyZone,
		v1.LabelTopologyRegion,
		v1.LabelFailureDomainBetaZone,
		v1.LabelFailureDomainBetaRegion,
		v1.LabelInstanceTypeStable,
		v1.LabelInstanceType,
		v1.LabelOSStable,
		v1.LabelArchStable,
		v1.LabelWindowsBuild,
		kubeletapis.LabelOS,
		kubeletapis.LabelArch,
	}

	needsUpdate := false
	if existingNode.Labels == nil {
		existingNode.Labels = make(map[string]string)
	}
	//Set default labels but make sure to not set labels with empty values
	for _, label := range defaultLabels {
		if _, hasInitialValue := initialNode.Labels[label]; !hasInitialValue {
			continue
		}

		if existingNode.Labels[label] != initialNode.Labels[label] {
			existingNode.Labels[label] = initialNode.Labels[label]
			needsUpdate = true
		}

		if existingNode.Labels[label] == "" {
			delete(existingNode.Labels, label)
		}
	}

	return needsUpdate
}

// 指示节点的attach/detach操作 是不是应由attach/detach控制器管理
func (kl *Kubelet) reconcileCMADAnnotationWithExistingNode(node, existingNode *v1.Node) bool {
	var (
		existingCMAAnnotation    = existingNode.Annotations[volutil.ControllerManagedAttachAnnotation]
		newCMAAnnotation, newSet = node.Annotations[volutil.ControllerManagedAttachAnnotation]
	)

	if newCMAAnnotation == existingCMAAnnotation {
		return false
	}

	// If the just-constructed node and the existing node do
	// not have the same value, update the existing node with
	// the correct value of the annotation.
	if !newSet {
		klog.InfoS("Controller attach-detach setting changed to false; updating existing Node")
		delete(existingNode.Annotations, volutil.ControllerManagedAttachAnnotation)
	} else {
		klog.InfoS("Controller attach-detach setting changed to true; updating existing Node")
		if existingNode.Annotations == nil {
			existingNode.Annotations = make(map[string]string)
		}
		existingNode.Annotations[volutil.ControllerManagedAttachAnnotation] = newCMAAnnotation
	}

	return true
}

// initialNode constructs the initial v1.Node for this Kubelet, incorporating node
// labels, information from the cloud provider, and Kubelet configuration.
func (kl *Kubelet) initialNode(ctx context.Context) (*v1.Node, error) {
	node := &v1.Node{ // 拼接节点信息字段
		ObjectMeta: metav1.ObjectMeta{
			Name: string(kl.nodeName),
			Labels: map[string]string{
				v1.LabelHostname:      kl.hostname,
				v1.LabelOSStable:      goruntime.GOOS,
				v1.LabelArchStable:    goruntime.GOARCH,
				kubeletapis.LabelOS:   goruntime.GOOS,
				kubeletapis.LabelArch: goruntime.GOARCH,
			},
		},
		Spec: v1.NodeSpec{
			Unschedulable: !kl.registerSchedulable,
		},
	}
	//如果有系统独特的标签就添加,linux上应该没有
	osLabels, err := getOSSpecificLabels()
	if err != nil {
		return nil, err
	}
	for label, value := range osLabels {
		node.Labels[label] = value
	}
	// 根据命令行传入的污点信息 --register-with-taints设置污点
	nodeTaints := make([]v1.Taint, len(kl.registerWithTaints))
	copy(nodeTaints, kl.registerWithTaints)
	unschedulableTaint := v1.Taint{
		Key:    v1.TaintNodeUnschedulable,
		Effect: v1.TaintEffectNoSchedule,
	}
	// 如果节点设置为不能被调度就添加污点信息 key为 node.kubernetes.io/unschedulable,value为NoSchedule
	// Taint node with TaintNodeUnschedulable when initializing
	// node to avoid race condition; refer to #63897 for more detail.
	if node.Spec.Unschedulable &&
		!taintutil.TaintExists(nodeTaints, &unschedulableTaint) {
		nodeTaints = append(nodeTaints, unschedulableTaint)
	}
	// 如果有外部云提供者就设置相关污点
	if kl.externalCloudProvider {
		taint := v1.Taint{
			Key:    cloudproviderapi.TaintExternalCloudProvider,
			Value:  "true",
			Effect: v1.TaintEffectNoSchedule,
		}

		nodeTaints = append(nodeTaints, taint)
	}
	if len(nodeTaints) > 0 {
		node.Spec.Taints = nodeTaints
	}
	// Initially, set NodeNetworkUnavailable to true.
	if kl.providerRequiresNetworkingConfiguration() {
		node.Status.Conditions = append(node.Status.Conditions, v1.NodeCondition{
			Type:               v1.NodeNetworkUnavailable,
			Status:             v1.ConditionTrue,
			Reason:             "NoRouteCreated",
			Message:            "Node created without a route",
			LastTransitionTime: metav1.NewTime(kl.clock.Now()),
		})
	}
	// 设置volume挂载卸载的 Annotations
	if kl.enableControllerAttachDetach {
		if node.Annotations == nil {
			node.Annotations = make(map[string]string)
		}

		klog.V(2).InfoS("Setting node annotation to enable volume controller attach/detach")
		node.Annotations[volutil.ControllerManagedAttachAnnotation] = "true"
	} else {
		klog.V(2).InfoS("Controller attach/detach is disabled for this node; Kubelet will attach and detach volumes")
	}
	// 是否保留TerminatedPod的Volume
	if kl.keepTerminatedPodVolumes {
		if node.Annotations == nil {
			node.Annotations = make(map[string]string)
		}
		klog.V(2).InfoS("Setting node annotation to keep pod volumes of terminated pods attached to the node")
		node.Annotations[volutil.KeepTerminatedPodVolumesAnnotation] = "true"
	}

	// @question: should this be place after the call to the cloud provider? which also applies labels
	// 检查用户设置的节点标签是否覆盖了默认的
	for k, v := range kl.nodeLabels {
		if cv, found := node.ObjectMeta.Labels[k]; found {
			klog.InfoS("the node label will overwrite default setting", "labelKey", k, "labelValue", v, "default", cv)
		}
		node.ObjectMeta.Labels[k] = v
	}

	if kl.providerID != "" {
		node.Spec.ProviderID = kl.providerID
	}
	// 公有云相关的
	if kl.cloud != nil {
		instances, ok := kl.cloud.Instances()
		if !ok {
			return nil, fmt.Errorf("failed to get instances from cloud provider")
		}

		// TODO: We can't assume that the node has credentials to talk to the
		// cloudprovider from arbitrary nodes. At most, we should talk to a
		// local metadata server here.
		var err error
		if node.Spec.ProviderID == "" {
			node.Spec.ProviderID, err = cloudprovider.GetInstanceProviderID(ctx, kl.cloud, kl.nodeName)
			if err != nil {
				return nil, err
			}
		}

		instanceType, err := instances.InstanceType(ctx, kl.nodeName)
		if err != nil {
			return nil, err
		}
		if instanceType != "" {
			klog.InfoS("Adding label from cloud provider", "labelKey", v1.LabelInstanceType, "labelValue", instanceType)
			node.ObjectMeta.Labels[v1.LabelInstanceType] = instanceType
			klog.InfoS("Adding node label from cloud provider", "labelKey", v1.LabelInstanceTypeStable, "labelValue", instanceType)
			node.ObjectMeta.Labels[v1.LabelInstanceTypeStable] = instanceType
		}
		// If the cloud has zone information, label the node with the zone information
		zones, ok := kl.cloud.Zones()
		if ok {
			zone, err := zones.GetZone(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get zone from cloud provider: %v", err)
			}
			if zone.FailureDomain != "" {
				klog.InfoS("Adding node label from cloud provider", "labelKey", v1.LabelFailureDomainBetaZone, "labelValue", zone.FailureDomain)
				node.ObjectMeta.Labels[v1.LabelFailureDomainBetaZone] = zone.FailureDomain
				klog.InfoS("Adding node label from cloud provider", "labelKey", v1.LabelTopologyZone, "labelValue", zone.FailureDomain)
				node.ObjectMeta.Labels[v1.LabelTopologyZone] = zone.FailureDomain
			}
			if zone.Region != "" {
				klog.InfoS("Adding node label from cloud provider", "labelKey", v1.LabelFailureDomainBetaRegion, "labelValue", zone.Region)
				node.ObjectMeta.Labels[v1.LabelFailureDomainBetaRegion] = zone.Region
				klog.InfoS("Adding node label from cloud provider", "labelKey", v1.LabelTopologyRegion, "labelValue", zone.Region)
				node.ObjectMeta.Labels[v1.LabelTopologyRegion] = zone.Region
			}
		}
	}
	// 通过预设的方法给node绑定状态属性
	kl.setNodeStatus(ctx, node)

	return node, nil
}

// 除了最后一次运行外,它不会击中apisserver,在每个循环中由fastStatusUpdateOnce调用.
// 它持有与syncNodeStatus相同的锁,并且在与syncNodeStatus并发调用时是线程安全的.它的返回值指示运行它的循环是否应该退出(最终运行),并且它还设置了kl.containerRuntimeReadyExpected.
func (kl *Kubelet) fastNodeStatusUpdate(ctx context.Context, timeout bool) (completed bool) {
	var _ = kl.syncNodeStatus // 的“轻量级”版本
	kl.syncNodeStatusMux.Lock()
	defer func() {
		kl.syncNodeStatusMux.Unlock()

		if completed {
			// containerRuntimeReadyExpected is read by updateRuntimeUp().
			// Not going for a more granular mutex as this path runs only once.
			kl.updateRuntimeMux.Lock()
			defer kl.updateRuntimeMux.Unlock()
			kl.containerRuntimeReadyExpected = true
		}
	}()

	if timeout {
		klog.ErrorS(nil, "如果节点在启动后没有及时准备就绪")
		return true
	}

	originalNode, err := kl.GetNode()
	if err != nil {
		klog.ErrorS(err, "Error getting the current node from lister")
		return false
	}

	readyIdx, originalNodeReady := nodeutil.GetNodeCondition(&originalNode.Status, v1.NodeReady)
	if readyIdx == -1 {
		klog.ErrorS(nil, "Node does not have NodeReady condition", "originalNode", originalNode)
		return false
	}

	if originalNodeReady.Status == v1.ConditionTrue {
		return true
	}

	kl.updateRuntimeUp() //运行初调用一次  ✅

	node, changed := kl.updateNode(ctx, originalNode) // 更新 CIDR

	if !changed {
		// We don't do markVolumesFromNode(node) here and leave it to the regular syncNodeStatus().
		return false
	}

	readyIdx, nodeReady := nodeutil.GetNodeCondition(&node.Status, v1.NodeReady)
	if readyIdx == -1 {
		klog.ErrorS(nil, "Node does not have NodeReady condition", "node", node)
		return false
	}

	if nodeReady.Status == v1.ConditionFalse {
		return false
	}

	klog.InfoS("快速更新节点状态,因为它刚刚准备好")
	if _, err := kl.patchNodeStatus(originalNode, node); err != nil {
		// The originalNode is probably stale, but we know that the current state of kubelet would turn
		// the node to be ready. Retry using syncNodeStatus() which fetches from the apiserver.
		klog.ErrorS(err, "Error updating node status, will retry with syncNodeStatus")

		// The reversed kl.syncNodeStatusMux.Unlock/Lock() below to allow kl.syncNodeStatus() execution.
		kl.syncNodeStatusMux.Unlock()
		kl.syncNodeStatus() // ✅
		// This lock action is unnecessary if we add a flag to check in the defer before unlocking it,
		// but having it here makes the logic a bit easier to read.
		kl.syncNodeStatusMux.Lock()
	}

	// We don't do markVolumesFromNode(node) here and leave it to the regular syncNodeStatus().
	return true
}

func (kl *Kubelet) syncNodeStatus() { // ✅
	kl.syncNodeStatusMux.Lock()
	defer kl.syncNodeStatusMux.Unlock()
	ctx := context.Background()

	if kl.kubeClient == nil || kl.heartbeatClient == nil {
		return
	}
	if kl.registerNode {
		// This will exit immediately if it doesn't need to do anything.
		kl.registerWithAPIServer() // ✅
	}
	if err := kl.updateNodeStatus(ctx); err != nil {
		klog.ErrorS(err, "Unable to update node status")
	}
}

// updateNodeStatus updates node status to master with retries if there is any
// change or enough time passed from the last sync.
func (kl *Kubelet) updateNodeStatus(ctx context.Context) error { // ✅
	klog.V(5).InfoS("Updating node status")
	for i := 0; i < nodeStatusUpdateRetry; i++ {
		if err := kl.tryUpdateNodeStatus(ctx, i); err != nil {
			if i > 0 && kl.onRepeatedHeartbeatFailure != nil {
				kl.onRepeatedHeartbeatFailure()
			}
			klog.ErrorS(err, "Error updating node status, will retry")
		} else {
			return nil
		}
	}
	return fmt.Errorf("update node status exceeds retry count")
}

// tryUpdateNodeStatus tries to update node status to master if there is any
// change or enough time passed from the last sync.
func (kl *Kubelet) tryUpdateNodeStatus(ctx context.Context, tryNumber int) error {
	// In large clusters, GET and PUT operations on Node objects coming
	// from here are the majority of load on apiserver and etcd.
	// To reduce the load on etcd, we are serving GET operations from
	// apiserver cache (the data might be slightly delayed but it doesn't
	// seem to cause more conflict - the delays are pretty small).
	// If it result in a conflict, all retries are served directly from etcd.
	opts := metav1.GetOptions{}
	if tryNumber == 0 {
		util.FromApiserverCache(&opts)
	}
	originalNode, err := kl.heartbeatClient.CoreV1().Nodes().Get(ctx, string(kl.nodeName), opts)
	if err != nil {
		return fmt.Errorf("error getting node %q: %v", kl.nodeName, err)
	}
	if originalNode == nil {
		return fmt.Errorf("nil %q node object", kl.nodeName)
	}

	node, changed := kl.updateNode(ctx, originalNode)
	shouldPatchNodeStatus := changed || kl.clock.Since(kl.lastStatusReportTime) >= kl.nodeStatusReportFrequency

	if !shouldPatchNodeStatus {
		kl.markVolumesFromNode(node)
		return nil
	}

	updatedNode, err := kl.patchNodeStatus(originalNode, node)
	if err == nil {
		kl.markVolumesFromNode(updatedNode)
	}
	return err
}

// 该函数返回更新后的节点对象和一个布尔值,指示是否有任何更改.// ✅
func (kl *Kubelet) updateNode(ctx context.Context, originalNode *v1.Node) (*v1.Node, bool) { // ✅
	node := originalNode.DeepCopy()

	podCIDRChanged := false
	if len(node.Spec.PodCIDRs) != 0 {
		// Pod CIDR could have been updated before, so we cannot rely on
		// node.Spec.PodCIDR being non-empty. We also need to know if pod CIDR is
		// actually changed.
		var err error
		podCIDRs := strings.Join(node.Spec.PodCIDRs, ",")
		if podCIDRChanged, err = kl.updatePodCIDR(ctx, podCIDRs); err != nil {
			klog.ErrorS(err, "Error updating pod CIDR")
		}
	}

	areRequiredLabelsNotPresent := false
	osName, osLabelExists := node.Labels[v1.LabelOSStable]
	if !osLabelExists || osName != goruntime.GOOS {
		if len(node.Labels) == 0 {
			node.Labels = make(map[string]string)
		}
		node.Labels[v1.LabelOSStable] = goruntime.GOOS
		areRequiredLabelsNotPresent = true
	}
	// Set the arch if there is a mismatch
	arch, archLabelExists := node.Labels[v1.LabelArchStable]
	if !archLabelExists || arch != goruntime.GOARCH {
		if len(node.Labels) == 0 {
			node.Labels = make(map[string]string)
		}
		node.Labels[v1.LabelArchStable] = goruntime.GOARCH
		areRequiredLabelsNotPresent = true
	}

	kl.setNodeStatus(ctx, node)

	changed := podCIDRChanged || nodeStatusHasChanged(&originalNode.Status, &node.Status) || areRequiredLabelsNotPresent
	return node, changed
}

func (kl *Kubelet) patchNodeStatus(originalNode, node *v1.Node) (*v1.Node, error) { // ✅
	// Patch the current status on the API server
	updatedNode, _, err := nodeutil.PatchNodeStatus(kl.heartbeatClient.CoreV1(), types.NodeName(kl.nodeName), originalNode, node) // ✅
	if err != nil {
		return nil, err
	}
	kl.lastStatusReportTime = kl.clock.Now()
	kl.setLastObservedNodeAddresses(updatedNode.Status.Addresses)
	return updatedNode, nil
}

// markVolumesFromNode updates volumeManager with VolumesInUse status from node.
//
// In the case of node status update being unnecessary, call with the fetched node.
// We must mark the volumes as ReportedInUse in volume manager's dsw even
// if no changes were made to the node status (no volumes were added or removed
// from the VolumesInUse list).
//
// The reason is that on a kubelet restart, the volume manager's dsw is
// repopulated and the volume ReportedInUse is initialized to false, while the
// VolumesInUse list from the Node object still contains the state from the
// previous kubelet instantiation.
//
// Once the volumes are added to the dsw, the ReportedInUse field needs to be
// synced from the VolumesInUse list in the Node.Status.
//
// The MarkVolumesAsReportedInUse() call cannot be performed in dsw directly
// because it does not have access to the Node object.
// This also cannot be populated on node status manager init because the volume
// may not have been added to dsw at that time.
//
// Or, after a successful node status update, call with updatedNode returned from
// the patch call, to mark the volumeInUse as reportedInUse to indicate
// those volumes are already updated in the node's status
func (kl *Kubelet) markVolumesFromNode(node *v1.Node) {
	kl.volumeManager.MarkVolumesAsReportedInUse(node.Status.VolumesInUse)
}

// recordNodeStatusEvent records an event of the given type with the given
// message for the node.
func (kl *Kubelet) recordNodeStatusEvent(eventType, event string) {
	klog.V(2).InfoS("Recording event message for node", "node", klog.KRef("", string(kl.nodeName)), "event", event)
	kl.recorder.Eventf(kl.nodeRef, eventType, event, "Node %s status is now: %s", kl.nodeName, event)
}

// recordEvent records an event for this node, the Kubelet's nodeRef is passed to the recorder
func (kl *Kubelet) recordEvent(eventType, event, message string) {
	kl.recorder.Eventf(kl.nodeRef, eventType, event, message)
}

// record if node schedulable change.
func (kl *Kubelet) recordNodeSchedulableEvent(ctx context.Context, node *v1.Node) error {
	kl.lastNodeUnschedulableLock.Lock()
	defer kl.lastNodeUnschedulableLock.Unlock()
	if kl.lastNodeUnschedulable != node.Spec.Unschedulable {
		if node.Spec.Unschedulable {
			kl.recordNodeStatusEvent(v1.EventTypeNormal, events.NodeNotSchedulable)
		} else {
			kl.recordNodeStatusEvent(v1.EventTypeNormal, events.NodeSchedulable)
		}
		kl.lastNodeUnschedulable = node.Spec.Unschedulable
	}
	return nil
}

// setNodeStatus fills in the Status fields of the given Node, overwriting
// any fields that are currently set.
// TODO(madhusudancs): Simplify the logic for setting node conditions and
// refactor the node status condition code out to a different file.
// 通过预设的方法给node绑定状态属性
func (kl *Kubelet) setNodeStatus(ctx context.Context, node *v1.Node) {
	for i, f := range kl.setNodeStatusFuncs {
		klog.V(5).InfoS("Setting node status condition code", "position", i, "node", klog.KObj(node))
		if err := f(ctx, node); err != nil {
			klog.ErrorS(err, "Failed to set some node status fields", "node", klog.KObj(node))
		}
	}
}

func (kl *Kubelet) setLastObservedNodeAddresses(addresses []v1.NodeAddress) {
	kl.lastObservedNodeAddressesMux.Lock()
	defer kl.lastObservedNodeAddressesMux.Unlock()
	kl.lastObservedNodeAddresses = addresses
}
func (kl *Kubelet) getLastObservedNodeAddresses() []v1.NodeAddress {
	kl.lastObservedNodeAddressesMux.RLock()
	defer kl.lastObservedNodeAddressesMux.RUnlock()
	return kl.lastObservedNodeAddresses
}

// 给节点绑定属性信息的工厂函数
func (kl *Kubelet) defaultNodeStatusFuncs() []func(context.Context, *v1.Node) error {
	// if cloud is not nil, we expect the cloud resource sync manager to exist
	var nodeAddressesFunc func() ([]v1.NodeAddress, error)
	if kl.cloud != nil {
		nodeAddressesFunc = kl.cloudResourceSyncManager.NodeAddresses
	}
	var validateHostFunc func() error
	if kl.appArmorValidator != nil {
		validateHostFunc = kl.appArmorValidator.ValidateHost
	}
	var setters []func(ctx context.Context, n *v1.Node) error
	setters = append(setters,
		// 设置IP,hostname
		nodestatus.NodeAddress(kl.nodeIPs, kl.nodeIPValidator, kl.hostname, kl.hostnameOverridden, kl.externalCloudProvider, kl.cloud, nodeAddressesFunc),
		// 节点绑定Capacity(代表总量)和Allocatable(代表节点上可供普通 Pod 消耗的资源量)
		nodestatus.MachineInfo(
			string(kl.nodeName),
			kl.maxPods,                      // 代表node上最多可以运行多少个pod 默认为110
			kl.podsPerCore,                  // 代表node上一个核最多跑多少个pod 默认为0
			kl.GetCachedMachineInfo,         // 获取机器信息的方法   staging/src/github.com/google/cadvisor/machine/info.go:57
			kl.containerManager.GetCapacity, // 获取机器容量信息的函数
			kl.containerManager.GetDevicePluginResourceCapacity, // 获取机器磁盘容量信息的函数
			kl.containerManager.GetNodeAllocatableReservation,
			kl.recordEvent, //
			kl.supportLocalStorageCapacityIsolation(), //
		),
		// 节点绑定版本信息
		nodestatus.VersionInfo(kl.cadvisor.VersionInfo, kl.containerRuntime.Type, kl.containerRuntime.Version),
		// kubelet 运行的ip+port
		nodestatus.DaemonEndpoints(kl.daemonEndpoints),
		// Images 节点上的镜像list 信息
		nodestatus.Images(kl.nodeStatusMaxImages, kl.imageManager.GetImageList),
		nodestatus.GoRuntime(),
	)
	// Volume limits
	setters = append(setters, nodestatus.VolumeLimits(kl.volumePluginMgr.ListVolumePluginWithLimits))

	setters = append(setters,
		nodestatus.MemoryPressureCondition(kl.clock.Now, kl.evictionManager.IsUnderMemoryPressure, kl.recordNodeStatusEvent),
		nodestatus.DiskPressureCondition(kl.clock.Now, kl.evictionManager.IsUnderDiskPressure, kl.recordNodeStatusEvent),
		nodestatus.PIDPressureCondition(kl.clock.Now, kl.evictionManager.IsUnderPIDPressure, kl.recordNodeStatusEvent),
		nodestatus.ReadyCondition(kl.clock.Now, kl.runtimeState.runtimeErrors, kl.runtimeState.networkErrors, kl.runtimeState.storageErrors,
			validateHostFunc, kl.containerManager.Status, kl.shutdownManager.ShutdownStatus, kl.recordNodeStatusEvent, kl.supportLocalStorageCapacityIsolation()),
		nodestatus.VolumesInUse(kl.volumeManager.ReconcilerStatesHasBeenSynced, kl.volumeManager.GetVolumesInUse),
		// TODO(mtaufen): I decided not to move this setter for now, since all it does is send an event
		// and record state back to the Kubelet runtime object. In the future, I'd like to isolate
		// these side-effects by decoupling the decisions to send events and partial status recording
		// from the Node setters.
		kl.recordNodeSchedulableEvent,
	)
	return setters
}

// Validate given node IP belongs to the current host
func validateNodeIP(nodeIP net.IP) error {
	// Honor IP limitations set in setNodeStatus()
	if nodeIP.To4() == nil && nodeIP.To16() == nil {
		return fmt.Errorf("nodeIP must be a valid IP address")
	}
	if nodeIP.IsLoopback() {
		return fmt.Errorf("nodeIP can't be loopback address")
	}
	if nodeIP.IsMulticast() {
		return fmt.Errorf("nodeIP can't be a multicast address")
	}
	if nodeIP.IsLinkLocalUnicast() {
		return fmt.Errorf("nodeIP can't be a link-local unicast address")
	}
	if nodeIP.IsUnspecified() {
		return fmt.Errorf("nodeIP can't be an all zeros address")
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip != nil && ip.Equal(nodeIP) {
			return nil
		}
	}
	return fmt.Errorf("node IP: %q not found in the host's network interfaces", nodeIP.String())
}

// ✅
func nodeStatusHasChanged(originalStatus *v1.NodeStatus, status *v1.NodeStatus) bool { // ✅
	if originalStatus == nil && status == nil {
		return false
	}
	if originalStatus == nil || status == nil {
		return true
	}

	// Compare node conditions here because we need to ignore the heartbeat timestamp.
	if nodeConditionsHaveChanged(originalStatus.Conditions, status.Conditions) {
		return true
	}

	// Compare other fields of NodeStatus.
	originalStatusCopy := originalStatus.DeepCopy()
	statusCopy := status.DeepCopy()
	originalStatusCopy.Conditions = nil
	statusCopy.Conditions = nil
	return !apiequality.Semantic.DeepEqual(originalStatusCopy, statusCopy)
}

// nodeConditionsHaveChanged compares the original node and current node's
// conditions and returns true if any change happens. The heartbeat timestamp is
// ignored.// ✅
func nodeConditionsHaveChanged(originalConditions []v1.NodeCondition, conditions []v1.NodeCondition) bool { // ✅
	if len(originalConditions) != len(conditions) {
		return true
	}

	originalConditionsCopy := make([]v1.NodeCondition, 0, len(originalConditions))
	originalConditionsCopy = append(originalConditionsCopy, originalConditions...)
	conditionsCopy := make([]v1.NodeCondition, 0, len(conditions))
	conditionsCopy = append(conditionsCopy, conditions...)

	sort.SliceStable(originalConditionsCopy, func(i, j int) bool { return originalConditionsCopy[i].Type < originalConditionsCopy[j].Type })
	sort.SliceStable(conditionsCopy, func(i, j int) bool { return conditionsCopy[i].Type < conditionsCopy[j].Type })

	replacedheartbeatTime := metav1.Time{}
	for i := range conditionsCopy {
		originalConditionsCopy[i].LastHeartbeatTime = replacedheartbeatTime
		conditionsCopy[i].LastHeartbeatTime = replacedheartbeatTime
		if !apiequality.Semantic.DeepEqual(&originalConditionsCopy[i], &conditionsCopy[i]) {
			return true
		}
	}
	return false
}
