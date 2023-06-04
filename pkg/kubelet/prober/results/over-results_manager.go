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

package results

import (
	"sync"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
)

// Manager provides a probe results cache and channel of updates.
type Manager interface {
	Get(kubecontainer.ContainerID) (Result, bool)   //
	Set(kubecontainer.ContainerID, Result, *v1.Pod) // 设置探测结果 , pod只在更新中设置
	Remove(kubecontainer.ContainerID)               // 移除缓存的容器探测结果
	Updates() <-chan Update                         // 创建一个通道,该通道在其 探测结果更改时 接收Update事件
}

type Result int // probe 探测的结果

const (
	Unknown Result = iota - 1
	Success
	Failure
)

func (r Result) String() string {
	switch r {
	case Success:
		return "Success"
	case Failure:
		return "Failure"
	default:
		return "UNKNOWN"
	}
}

// ToPrometheusType translates a Result to a form which is better understood by prometheus.
func (r Result) ToPrometheusType() float64 {
	switch r {
	case Success:
		return 0
	case Failure:
		return 1
	default:
		return -1
	}
}

// Update is an enum of the types of updates sent over the Updates channel.
type Update struct {
	ContainerID kubecontainer.ContainerID
	Result      Result
	PodUID      types.UID
}

// Manager implementation.
type manager struct {
	// guards the cache
	sync.RWMutex
	// map of container ID -> probe Result
	cache map[kubecontainer.ContainerID]Result
	// channel of updates
	updates chan Update
}

var _ Manager = &manager{}

// NewManager creates and returns an empty results manager.
func NewManager() Manager {
	return &manager{
		cache:   make(map[kubecontainer.ContainerID]Result),
		updates: make(chan Update, 20),
	}
}

func (m *manager) Get(id kubecontainer.ContainerID) (Result, bool) {
	m.RLock()
	defer m.RUnlock()
	result, found := m.cache[id]
	return result, found
}

func (m *manager) Set(id kubecontainer.ContainerID, result Result, pod *v1.Pod) {
	if m.setInternal(id, result) {
		m.updates <- Update{id, result, pod.UID}
	}
}

// 判断是否应该发送更新
func (m *manager) setInternal(id kubecontainer.ContainerID, result Result) bool {
	m.Lock()
	defer m.Unlock()
	prev, exists := m.cache[id]
	if !exists || prev != result {
		m.cache[id] = result
		return true
	}
	return false
}

func (m *manager) Remove(id kubecontainer.ContainerID) {
	m.Lock()
	defer m.Unlock()
	delete(m.cache, id)
}

func (m *manager) Updates() <-chan Update {
	return m.updates
}
