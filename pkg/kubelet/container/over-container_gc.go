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

package container

import (
	"context"
	"fmt"
	"time"

	"k8s.io/klog/v2"
)

// GCPolicy specifies a policy for garbage collecting containers.
type GCPolicy struct {
	MinAge             time.Duration // 是容器可以被执行垃圾回收的最小生命周期,零表示没有限制.
	MaxPerPodContainer int           // 是每个 pod 内允许存在的死亡容器的最大数量,小于零表示没有限制.
	MaxContainers      int           // 是全部死亡容器的最大数量
}

// MaxPerPodContainer 和 MaxContainer 在某些场景下可能会存在冲突
//
//- 例如在保证每个 pod 内死亡容器的最大数量（MaxPerPodContainer）的条件下可能会超过 允许存在的全部死亡容器的最大数量（MaxContainer）
//- MaxPerPodContainer 在这种情况下会被进行调整： 最坏的情况是将 MaxPerPodContainer 降级为 1,并驱逐最老的容器
//- 此外,pod 内已经被删除的容器一旦年龄超过 MinAge 就会被清理.

type GC interface {
	GarbageCollect(ctx context.Context) error
	DeleteAllUnusedContainers(ctx context.Context) error
}

// SourcesReadyProvider knows how to determine if configuration sources are ready
type SourcesReadyProvider interface {
	// AllReady returns true if the currently configured sources have all been seen.
	AllReady() bool
}

// TODO(vmarmol): Preferentially remove pod infra containers.
type realContainerGC struct {
	runtime              Runtime
	policy               GCPolicy
	sourcesReadyProvider SourcesReadyProvider // 一个ready的提供者,意思是ready后就可以进行gc了
}

// NewContainerGC creates a new instance of GC with the specified policy.
func NewContainerGC(runtime Runtime, policy GCPolicy, sourcesReadyProvider SourcesReadyProvider) (GC, error) {
	if policy.MinAge < 0 {
		return nil, fmt.Errorf("invalid minimum garbage collection age: %v", policy.MinAge)
	}

	return &realContainerGC{
		runtime:              runtime,
		policy:               policy,
		sourcesReadyProvider: sourcesReadyProvider,
	}, nil
}

func (cgc *realContainerGC) GarbageCollect(ctx context.Context) error {
	return cgc.runtime.GarbageCollect(ctx, cgc.policy, cgc.sourcesReadyProvider.AllReady(), false)
}

func (cgc *realContainerGC) DeleteAllUnusedContainers(ctx context.Context) error {
	klog.InfoS("Attempting to delete unused containers")
	return cgc.runtime.GarbageCollect(ctx, cgc.policy, cgc.sourcesReadyProvider.AllReady(), true)
}
