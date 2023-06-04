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

//go:generate mockgen -source=types.go -destination=testing/cadvisor_mock.go -package=testing Interface
package cadvisor

import (
	"github.com/google/cadvisor/events"
	cadvisorapi "github.com/google/cadvisor/info/v1"
	cadvisorapiv2 "github.com/google/cadvisor/info/v2"
)

// Interface is an abstract interface for testability.  It abstracts the interface to cAdvisor.
type Interface interface {
	Start() error
	DockerContainer(name string, req *cadvisorapi.ContainerInfoRequest) (cadvisorapi.ContainerInfo, error)
	ContainerInfo(name string, req *cadvisorapi.ContainerInfoRequest) (*cadvisorapi.ContainerInfo, error)
	ContainerInfoV2(name string, options cadvisorapiv2.RequestOptions) (map[string]cadvisorapiv2.ContainerInfo, error)
	GetRequestedContainersInfo(containerName string, options cadvisorapiv2.RequestOptions) (map[string]*cadvisorapi.ContainerInfo, error)
	SubcontainerInfo(name string, req *cadvisorapi.ContainerInfoRequest) (map[string]*cadvisorapi.ContainerInfo, error)
	MachineInfo() (*cadvisorapi.MachineInfo, error)
	VersionInfo() (*cadvisorapi.VersionInfo, error)
	ImagesFsInfo() (cadvisorapiv2.FsInfo, error)                       // 返回有关存储容器镜像的文件系统的使用情况信息.
	RootFsInfo() (cadvisorapiv2.FsInfo, error)                         // 返回有关根文件系统的使用情况信息.
	WatchEvents(request *events.Request) (*events.EventChannel, error) // 获取通过传递的通道传输的符合请求条件的事件流.
	GetDirFsInfo(path string) (cadvisorapiv2.FsInfo, error)            // ✅获取包含给定文件的文件系统的文件系统信息.
}

// ImageFsInfoProvider informs cAdvisor how to find imagefs for container images.
type ImageFsInfoProvider interface {
	// ImageFsInfoLabel returns the label cAdvisor should use to find the filesystem holding container images.
	ImageFsInfoLabel() (string, error)
}
