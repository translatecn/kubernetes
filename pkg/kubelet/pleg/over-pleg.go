/*
Copyright 2015 The Kubernetes Authors.

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

package pleg

import (
	"time"

	"k8s.io/apimachinery/pkg/types"
)

// PodLifeCycleEventType define the event type of pod life cycle events.
type PodLifeCycleEventType string

// RelistDuration relist阈值需要大于relist周期时间，因为relist时间可能会有很大的变化。设置一个保守的阈值可以避免在健康和不健康之间反复切换。
//
// 在 Kubernetes 中，relisting 是指 kubelet 重新获取 Pod 列表的过程。kubelet 周期性地从 API 服务器获取 Pod 列表，并在本地缓存中维护这些信息。当 kubelet 检测到 Pod 状态发生变化时，它会重新获取 Pod 列表，以确保它具有最新的状态信息。
//
// 在relist周期时间内，kubelet 可能会多次重新获取 Pod 列表。如果relist阈值太低，可能会导致 kubelet 在健康和不健康之间反复切换。因此，建议设置一个保守的relist阈值，以避免这种情况的发生。
type RelistDuration struct {
	// The period for relisting.
	RelistPeriod time.Duration
	// The relisting threshold needs to be greater than the relisting period +
	// the relisting time, which can vary significantly. Set a conservative
	// threshold to avoid flipping between healthy and unhealthy.
	RelistThreshold time.Duration
}

const (
	ContainerStarted PodLifeCycleEventType = "ContainerStarted" // 容器已启动并正在运行。
	ContainerDied    PodLifeCycleEventType = "ContainerDied"    // 容器已退出。
	ContainerRemoved PodLifeCycleEventType = "ContainerRemoved" // 容器已被删除。
	PodSync          PodLifeCycleEventType = "PodSync"          // 用于触发同步 Pod 的操作，当观察到的 Pod 状态的变化无法被上述任何单个事件捕获时使用。
	ContainerChanged PodLifeCycleEventType = "ContainerChanged" // 容器状态发生了未知的更改。
)

// PodLifecycleEvent is an event that reflects the change of the pod state.
type PodLifecycleEvent struct {
	ID   types.UID             // pod id
	Type PodLifeCycleEventType //
	Data interface{}           //   - ContainerStarted/ContainerStopped: the container name (string).- All other event types: unused.
}

// PodLifecycleEventGenerator contains functions for generating pod life cycle events.
type PodLifecycleEventGenerator interface {
	Start()
	Stop()
	Update(relistDuration *RelistDuration)
	Watch() chan *PodLifecycleEvent
	Healthy() (bool, error)
	Relist()
}
