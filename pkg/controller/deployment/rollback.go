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

package deployment

import (
	"context"
	"fmt"
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	apps "k8s.io/api/apps/v1"
	"k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	deploymentutil "k8s.io/kubernetes/pkg/controller/deployment/util"
)

// rollback the deployment to the specified revision. In any case cleanup the rollback spec.
func (dc *DeploymentController) rollback(ctx context.Context, d *apps.Deployment, rsList []*apps.ReplicaSet) error {
	// 拿到所有此deployment关连的rs
	newRS, allOldRSs, err := dc.getAllReplicaSetsAndSyncRevision(ctx, d, rsList, true)
	if err != nil {
		return err
	}

	// 返回需要回滚的版本
	allRSs := append(allOldRSs, newRS)
	rollbackTo := getRollbackTo(d)
	// If rollback revision is 0, rollback to the last revision
	if rollbackTo.Revision == 0 {
		if rollbackTo.Revision = deploymentutil.LastRevision(allRSs); rollbackTo.Revision == 0 {
			// If we still can't find the last revision, gives up rollback
			dc.emitRollbackWarningEvent(d, deploymentutil.RollbackRevisionNotFound, "Unable to find last revision.")
			// Gives up rollback
			return dc.updateDeploymentAndClearRollbackTo(ctx, d)
		}
	}
	// 遍历上面的rs，获取版本，如果版本与需要回滚的版本一致，调用rollbackToTemplate方法
	for _, rs := range allRSs {
		v, err := deploymentutil.Revision(rs)
		if err != nil {
			klog.V(4).Infof("Unable to extract revision from deployment's replica set %q: %v", rs.Name, err)
			continue
		}
		if v == rollbackTo.Revision {
			klog.V(4).Infof("Found replica set %q with desired revision %d", rs.Name, v)
			// rollback by copying podTemplate.Spec from the replica set
			// revision number will be incremented during the next getAllReplicaSetsAndSyncRevision call
			// no-op if the spec matches current deployment's podTemplate.Spec
			// 滚动更新主逻辑
			performedRollback, err := dc.rollbackToTemplate(ctx, d, rs)
			if performedRollback && err == nil {
				dc.emitRollbackNormalEvent(d, fmt.Sprintf("Rolled back deployment %q to revision %d", d.Name, rollbackTo.Revision))
			}
			return err
		}
	}
	dc.emitRollbackWarningEvent(d, deploymentutil.RollbackRevisionNotFound, "Unable to find the revision to rollback to.")
	// Gives up rollback
	return dc.updateDeploymentAndClearRollbackTo(ctx, d)
}

// rollbackToTemplate compares the templates of the provided deployment and replica set and
// updates the deployment with the replica set template in case they are different. It also
// cleans up the rollback spec so subsequent requeues of the deployment won't end up in here.
// rollbackToTemplate 比较提供的deployment和rs的模板
// 如果不同，则使用rs模板更新deployment。
// 它还会清理回滚规范，因此后续的部署重新排队不会在这里结束。
func (dc *DeploymentController) rollbackToTemplate(ctx context.Context, d *apps.Deployment, rs *apps.ReplicaSet) (bool, error) {
	performedRollback := false
	if !deploymentutil.EqualIgnoreHash(&d.Spec.Template, &rs.Spec.Template) {
		klog.V(4).Infof("Rolling back deployment %q to template spec %+v", d.Name, rs.Spec.Template.Spec)
		deploymentutil.SetFromReplicaSetTemplate(d, rs.Spec.Template)
		// set RS (the old RS we'll rolling back to) annotations back to the deployment;
		// otherwise, the deployment's current annotations (should be the same as current new RS) will be copied to the RS after the rollback.
		//
		// For example,
		// A Deployment has old RS1 with annotation {change-cause:create}, and new RS2 {change-cause:edit}.
		// Note that both annotations are copied from Deployment, and the Deployment should be annotated {change-cause:edit} as well.
		// Now, rollback Deployment to RS1, we should update Deployment's pod-template and also copy annotation from RS1.
		// Deployment is now annotated {change-cause:create}, and we have new RS1 {change-cause:create}, old RS2 {change-cause:edit}.
		//
		// If we don't copy the annotations back from RS to deployment on rollback, the Deployment will stay as {change-cause:edit},
		// and new RS1 becomes {change-cause:edit} (copied from deployment after rollback), old RS2 {change-cause:edit}, which is not correct.
		deploymentutil.SetDeploymentAnnotationsTo(d, rs)
		performedRollback = true
	} else {
		klog.V(4).Infof("Rolling back to a revision that contains the same template as current deployment %q, skipping rollback...", d.Name)
		eventMsg := fmt.Sprintf("The rollback revision contains the same template as current deployment %q", d.Name)
		dc.emitRollbackWarningEvent(d, deploymentutil.RollbackTemplateUnchanged, eventMsg)
	}

	return performedRollback, dc.updateDeploymentAndClearRollbackTo(ctx, d)
}

func (dc *DeploymentController) emitRollbackWarningEvent(d *apps.Deployment, reason, message string) {
	dc.eventRecorder.Eventf(d, v1.EventTypeWarning, reason, message)
}

func (dc *DeploymentController) emitRollbackNormalEvent(d *apps.Deployment, message string) {
	dc.eventRecorder.Eventf(d, v1.EventTypeNormal, deploymentutil.RollbackDone, message)
}

// updateDeploymentAndClearRollbackTo sets .spec.rollbackTo to nil and update the input deployment
// It is assumed that the caller will have updated the deployment template appropriately (in case
// we want to rollback).
// updateDeploymentAndClearRollbackTo 将 .spec.rollbackTo 设置为 nil 并更新deployment
// 假设caller已经适当更新deployment模板。
func (dc *DeploymentController) updateDeploymentAndClearRollbackTo(ctx context.Context, d *apps.Deployment) error {
	klog.V(4).Infof("Cleans up rollbackTo of deployment %q", d.Name)
	setRollbackTo(d, nil)
	_, err := dc.client.AppsV1().Deployments(d.Namespace).Update(ctx, d, metav1.UpdateOptions{})
	return err
}

// TODO: Remove this when extensions/v1beta1 and apps/v1beta1 Deployment are dropped.
// 如何查看rollback版本：使用annotation的key来判断
func getRollbackTo(d *apps.Deployment) *extensions.RollbackConfig {
	// Extract the annotation used for round-tripping the deprecated RollbackTo field.
	revision := d.Annotations[apps.DeprecatedRollbackTo]
	if revision == "" {
		return nil
	}
	revision64, err := strconv.ParseInt(revision, 10, 64)
	if err != nil {
		// If it's invalid, ignore it.
		return nil
	}
	return &extensions.RollbackConfig{
		Revision: revision64,
	}
}

// TODO: Remove this when extensions/v1beta1 and apps/v1beta1 Deployment are dropped.
func setRollbackTo(d *apps.Deployment, rollbackTo *extensions.RollbackConfig) {
	if rollbackTo == nil {
		delete(d.Annotations, apps.DeprecatedRollbackTo)
		return
	}
	if d.Annotations == nil {
		d.Annotations = make(map[string]string)
	}
	d.Annotations[apps.DeprecatedRollbackTo] = strconv.FormatInt(rollbackTo.Revision, 10)
}
