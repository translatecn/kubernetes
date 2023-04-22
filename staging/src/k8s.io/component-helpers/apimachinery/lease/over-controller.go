/*
Copyright 2018 The Kubernetes Authors.

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

package lease

import (
	"context"
	"fmt"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	coordclientset "k8s.io/client-go/kubernetes/typed/coordination/v1"
	"k8s.io/utils/clock"
	"k8s.io/utils/pointer"

	"k8s.io/klog/v2"
)

const (
	// maxUpdateRetries is the number of immediate, successive retries the controller will attempt
	// when renewing the lease before it waits for the renewal interval before trying again,
	// similar to what we do for node status retries
	maxUpdateRetries = 5
	// maxBackoff is the maximum sleep time during backoff (e.g. in backoffEnsureLease)
	maxBackoff = 7 * time.Second
)

// Controller manages creating and renewing the lease for this component (kube-apiserver, kubelet, etc.)
type Controller interface {
	Run(stopCh <-chan struct{})
}

// ProcessLeaseFunc processes the given lease in-place
type ProcessLeaseFunc func(*coordinationv1.Lease) error

type controller struct {
	client                     clientset.Interface           //
	leaseClient                coordclientset.LeaseInterface //
	holderIdentity             string                        // 主机
	leaseName                  string                        //
	leaseNamespace             string                        //
	leaseDurationSeconds       int32                         // 租约的持续时间（以秒为单位）
	renewInterval              time.Duration                 // 租约续约的间隔时间
	clock                      clock.Clock                   //
	onRepeatedHeartbeatFailure func()                        // 重复心跳失败时要执行的操作
	latestLease                *coordinationv1.Lease         // 控制器最近更新或创建的租约.
	newLeasePostProcessFunc    ProcessLeaseFunc              // 在每次创建/刷新租约之前自定义租约对象（例如设置 OwnerReference）.
}

// NewController ✅
func NewController(clock clock.Clock, client clientset.Interface, holderIdentity string,
	leaseDurationSeconds int32,
	onRepeatedHeartbeatFailure func(),
	renewInterval time.Duration,
	leaseName, leaseNamespace string,
	newLeasePostProcessFunc ProcessLeaseFunc) Controller {
	var leaseClient coordclientset.LeaseInterface
	if client != nil {
		leaseClient = client.CoordinationV1().Leases(leaseNamespace)
	}
	return &controller{
		client:                     client,
		leaseClient:                leaseClient,
		holderIdentity:             holderIdentity,
		leaseName:                  leaseName,
		leaseNamespace:             leaseNamespace,
		leaseDurationSeconds:       leaseDurationSeconds,
		renewInterval:              renewInterval,
		clock:                      clock,
		onRepeatedHeartbeatFailure: onRepeatedHeartbeatFailure,
		newLeasePostProcessFunc:    newLeasePostProcessFunc,
	}
}

// Run runs the controller
func (c *controller) Run(stopCh <-chan struct{}) {
	if c.leaseClient == nil {
		klog.Infof("lease controller has nil lease client, will not claim or renew leases")
		return
	}
	wait.JitterUntil(c.sync, c.renewInterval, 0.04, true, stopCh)
}

func (c *controller) sync() {
	if c.latestLease != nil {
		//只要租约没有被其他代理（或极少被其他代理）更新,我们就可以乐观地假设自上次更新以来它没有改变,并尝试基于那个时间的版本进行更新.
		//这样,我们可以避免 GET 调用并减少对 etcd 和 kube-apiserver 的负载.
		//如果在某个时候其他代理也频繁更新租约对象,这可能会导致性能下降,因为我们最终会调用额外的 GET/PUT - 在这一点上,整个 "if" 应该被删除.
		err := c.retryUpdateLease(c.latestLease)
		if err == nil {
			return
		}
		klog.Infof("failed to update lease using latest lease, fallback to ensure lease, err: %v", err)
	}

	lease, created := c.backoffEnsureLease()
	c.latestLease = lease
	// we don't need to update the lease if we just created it
	if !created && lease != nil {
		if err := c.retryUpdateLease(lease); err != nil {
			klog.Errorf("%v, will retry after %v", err, c.renewInterval)
		}
	}
}

// backoffEnsureLease attempts to create the lease if it does not exist,
// and uses exponentially increasing waits to prevent overloading the API server
// with retries. Returns the lease, and true if this call created the lease,
// false otherwise.
func (c *controller) backoffEnsureLease() (*coordinationv1.Lease, bool) {
	var (
		lease   *coordinationv1.Lease
		created bool
		err     error
	)
	sleep := 100 * time.Millisecond
	for {
		lease, created, err = c.ensureLease()
		if err == nil {
			break
		}
		sleep = minDuration(2*sleep, maxBackoff)
		klog.Errorf("failed to ensure lease exists, will retry in %v, error: %v", sleep, err)
		// backoff wait
		c.clock.Sleep(sleep)
	}
	return lease, created
}

// ensureLease creates the lease if it does not exist. Returns the lease and
// a bool (true if this call created the lease), or any error that occurs.
func (c *controller) ensureLease() (*coordinationv1.Lease, bool, error) {
	lease, err := c.leaseClient.Get(context.TODO(), c.leaseName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// lease does not exist, create it.
		leaseToCreate, err := c.newLease(nil)
		// An error occurred during allocating the new lease (likely from newLeasePostProcessFunc).
		// Given that we weren't able to set the lease correctly, we simply
		// not create it this time - we will retry in the next iteration.
		if err != nil {
			return nil, false, nil
		}
		lease, err := c.leaseClient.Create(context.TODO(), leaseToCreate, metav1.CreateOptions{})
		if err != nil {
			return nil, false, err
		}
		return lease, true, nil
	} else if err != nil {
		// unexpected error getting lease
		return nil, false, err
	}
	// lease already existed
	return lease, false, nil
}

// retryUpdateLease attempts to update the lease for maxUpdateRetries,
// call this once you're sure the lease has been created
func (c *controller) retryUpdateLease(base *coordinationv1.Lease) error {
	for i := 0; i < maxUpdateRetries; i++ {
		leaseToUpdate, _ := c.newLease(base)
		lease, err := c.leaseClient.Update(context.TODO(), leaseToUpdate, metav1.UpdateOptions{})
		if err == nil {
			c.latestLease = lease
			return nil
		}
		klog.Errorf("failed to update lease, error: %v", err)
		// OptimisticLockError requires getting the newer version of lease to proceed.
		if apierrors.IsConflict(err) {
			base, _ = c.backoffEnsureLease()
			continue
		}
		if i > 0 && c.onRepeatedHeartbeatFailure != nil {
			c.onRepeatedHeartbeatFailure()
		}
	}
	return fmt.Errorf("failed %d attempts to update lease", maxUpdateRetries)
}

// newLease constructs a new lease if base is nil, or returns a copy of base
// with desired state asserted on the copy.
// Note that an error will block lease CREATE, causing the CREATE to be retried in
// the next iteration; but the error won't block lease refresh (UPDATE).
func (c *controller) newLease(base *coordinationv1.Lease) (*coordinationv1.Lease, error) {
	// Use the bare minimum set of fields; other fields exist for debugging/legacy,
	// but we don't need to make component heartbeats more complicated by using them.
	var lease *coordinationv1.Lease
	if base == nil {
		lease = &coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{
				Name:      c.leaseName,
				Namespace: c.leaseNamespace,
			},
			Spec: coordinationv1.LeaseSpec{
				HolderIdentity:       pointer.StringPtr(c.holderIdentity),
				LeaseDurationSeconds: pointer.Int32Ptr(c.leaseDurationSeconds),
			},
		}
	} else {
		lease = base.DeepCopy()
	}
	lease.Spec.RenewTime = &metav1.MicroTime{Time: c.clock.Now()}

	if c.newLeasePostProcessFunc != nil {
		err := c.newLeasePostProcessFunc(lease)
		return lease, err
	}

	return lease, nil
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
