/*
Copyright 2017 The Kubernetes Authors.

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

package options

import (
	"k8s.io/kubernetes/pkg/kubelet/config"
	kubetypes "k8s.io/kubernetes/pkg/kubelet/types"
)

const (
	// When these values are updated, also update test/utils/image/manifest.go
	defaultPodSandboxImageName    = "registry.k8s.io/pause"
	defaultPodSandboxImageVersion = "3.9"
)

var (
	defaultPodSandboxImage = defaultPodSandboxImageName +
		":" + defaultPodSandboxImageVersion
)

// NewContainerRuntimeOptions will create a new ContainerRuntimeOptions with
// default values.
func NewContainerRuntimeOptions() *config.ContainerRuntimeOptions {
	return &config.ContainerRuntimeOptions{
		ContainerRuntime: kubetypes.RemoteContainerRuntime,
		PodSandboxImage:  defaultPodSandboxImage,
	}
}

// Pause 镜像是 Kubernetes 中的一个特殊镜像，它的作用是协调容器的网络和存储等资源。Pause 镜像是一个非常小的镜像，只包含一个空的容器，它会在 Kubernetes 中的每个 Pod 中作为第一个容器运行。
//
//
//当一个 Pod 中有多个容器时，Pause 容器会协调这些容器之间的网络和存储资源，并提供一个共享的网络命名空间和卷挂载点。当容器启动时，它们会加入 Pause 容器所在的网络命名空间，以便能够相互通信和访问共享的存储卷。
//
//
//除此之外，Pause 容器还会监控 Pod 中的其他容器，以确保它们正常运行。如果其中一个容器出现故障或崩溃，Pause 容器会自动重启它，以确保应用程序的可用性和稳定性。
//
//
//需要注意的是，Pause 镜像是一个非常基础的镜像，它不包含任何应用程序或服务，只是用于协调和管理容器的资源。在 Kubernetes 中，每个 Pod 都会运行一个 Pause 容器，以确保容器之间的网络和存储资源得到正确的管理和协调。
