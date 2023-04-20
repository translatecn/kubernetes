/*
Copyright 2021 The Kubernetes Authors.

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

package request

import (
	"errors"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
)

const (
	// type deletion (it applies mostly to CRD) is not a very frequent
	// operation so we can afford to prune the cache at a large interval.
	// at the same time, we also want to make sure that the scalability
	// tests hit this code path.
	pruneInterval = 1 * time.Hour

	// the storage layer polls for object count at every 1m interval, we will allow up to 2-3 transient failures to get the latest count for a given resource.
	staleTolerationThreshold = 3 * time.Minute
)

var (
	// ObjectCountNotFoundErr is returned when the object count for
	// a given resource is not being tracked.
	ObjectCountNotFoundErr = errors.New("object count not found for the given resource")

	// ObjectCountStaleErr is returned when the object count for a
	// given resource has gone stale due to transient failures.
	ObjectCountStaleErr = errors.New("object count has gone stale for the given resource")
)

// StorageObjectCountTracker is an interface that is used to keep track of
// of the total number of objects for each resource.
// {group}.{resource} is used as the key name to update and retrieve
// the total number of objects for a given resource.
type StorageObjectCountTracker interface {
	// Set is invoked to update the current number of total
	// objects for the given resource
	Set(string, int64)
	Get(string) (int64, error) // 获取每种资源的请求数量
	// RunUntil starts all the necessary maintenance.
	RunUntil(stopCh <-chan struct{})
}

// NewStorageObjectCountTracker 跟踪每个资源的对象总数
func NewStorageObjectCountTracker() StorageObjectCountTracker {
	return &ObjectCountTracker{
		clock:  &clock.RealClock{},
		counts: map[string]*timestampedCount{},
	}
}

// timestampedCount stores the count of a given resource with a last updated
// timestamp so we can prune it after it goes stale for certain threshold.
type timestampedCount struct {
	count         int64
	lastUpdatedAt time.Time
}

// ObjectCountTracker implements StorageObjectCountTracker with
// reader/writer mutual exclusion lock.
type ObjectCountTracker struct {
	clock clock.PassiveClock

	lock   sync.RWMutex
	counts map[string]*timestampedCount
}

func (t *ObjectCountTracker) Set(groupResource string, count int64) {
	if count <= -1 {
		// a value of -1 indicates that the 'Count' call failed to contact
		// the storage layer, in most cases this error can be transient.
		// we will continue to work with the count that is in the cache
		// up to a certain threshold defined by staleTolerationThreshold.
		// in case this becomes a non transient error then the count for
		// the given resource will will eventually be removed from
		// the cache by the pruner.
		return
	}

	now := t.clock.Now()

	// lock for writing
	t.lock.Lock()
	defer t.lock.Unlock()

	if item, ok := t.counts[groupResource]; ok {
		item.count = count
		item.lastUpdatedAt = now
		return
	}

	t.counts[groupResource] = &timestampedCount{
		count:         count,
		lastUpdatedAt: now,
	}
}

func (t *ObjectCountTracker) Get(groupResource string) (int64, error) {
	staleThreshold := t.clock.Now().Add(-staleTolerationThreshold)

	t.lock.RLock()
	defer t.lock.RUnlock()

	if item, ok := t.counts[groupResource]; ok {
		if item.lastUpdatedAt.Before(staleThreshold) {
			// 对象计数过时表明出现了退化,因此我们应该在此处保守,并为此列表请求分配最大座位数.// 注意：如果删除了CRD,则其计数将首先变为过时状态,然后修剪器将最终从缓存中删除CRD.
			return item.count, ObjectCountStaleErr
		}
		return item.count, nil
	}
	return 0, ObjectCountNotFoundErr
}

// RunUntil runs all the necessary maintenance.
func (t *ObjectCountTracker) RunUntil(stopCh <-chan struct{}) {
	wait.PollUntil(
		pruneInterval,
		func() (bool, error) {
			// always prune at every pruneInterval
			return false, t.prune(pruneInterval)
		}, stopCh)
	klog.InfoS("StorageObjectCountTracker pruner is exiting")
}

func (t *ObjectCountTracker) prune(threshold time.Duration) error {
	oldestLastUpdatedAtAllowed := t.clock.Now().Add(-threshold)

	// lock for writing
	t.lock.Lock()
	defer t.lock.Unlock()

	for groupResource, count := range t.counts {
		if count.lastUpdatedAt.After(oldestLastUpdatedAtAllowed) {
			continue
		}
		delete(t.counts, groupResource)
	}

	return nil
}
