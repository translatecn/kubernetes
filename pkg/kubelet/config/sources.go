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

// Package config implements the pod configuration readers.
package config

import (
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"
)

// SourcesReadyFn is function that returns true if the specified sources have been seen.
type SourcesReadyFn func(sourcesSeen sets.String) bool

// SourcesReady 跟踪 kubelet 所管理的已配置源的集合
type SourcesReady interface {
	AddSource(source string) // 将指定的源添加到所管理的源集合中
	AllReady() bool          // 如果所有当前配置的源都已经被看到,则返回 true.
}

// NewSourcesReady returns a SourcesReady with the specified function.
func NewSourcesReady(sourcesReadyFn SourcesReadyFn) SourcesReady {
	return &sourcesImpl{
		sourcesSeen:    sets.NewString(),
		sourcesReadyFn: sourcesReadyFn,
	}
}

// sourcesImpl implements SourcesReady.  It is thread-safe.
type sourcesImpl struct {
	// lock protects access to sources seen.
	lock sync.RWMutex
	// set of sources seen.
	sourcesSeen sets.String
	// sourcesReady is a function that evaluates if the sources are ready.
	sourcesReadyFn SourcesReadyFn
}

// Add adds the specified source to the set of sources managed.
func (s *sourcesImpl) AddSource(source string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.sourcesSeen.Insert(source)
}

// AllReady returns true if each configured source is ready.
func (s *sourcesImpl) AllReady() bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.sourcesReadyFn(s.sourcesSeen)
}
