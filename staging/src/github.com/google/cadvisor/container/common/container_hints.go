// Copyright 2014 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Unmarshal's a Containers description json file. The json file contains
// an array of ContainerHint structs, each with a container's id and networkInterface
// This allows collecting stats about network interfaces configured outside docker
// and lxc
package common

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"os"
)

// ArgContainerHints 在cAdvisor中，容器提示文件（container hints file）是一个文本文件，用于指定容器的元数据，例如容器的名称、标签、环境变量等等。
// 容器提示文件通常位于cAdvisor的配置目录中，可以由用户自定义。cAdvisor在启动时会读取容器提示文件，并根据其中的信息来识别和管理容器。
// 容器提示文件的位置取决于cAdvisor的配置，可以通过命令行参数或配置文件来指定。以下是一些常见的位置：
// /etc/cadvisor/container_hints.yaml：在Linux系统中，容器提示文件通常位于/etc/cadvisor目录中，文件名为container_hints.yaml。
// /usr/local/etc/cadvisor/container_hints.yaml：在FreeBSD等系统中，容器提示文件通常位于/usr/local/etc/cadvisor目录中。
// 自定义位置：用户也可以通过命令行参数或配置文件来指定容器提示文件的位置，例如--container_hints=/path/to/container_hints.yaml。
var ArgContainerHints = flag.String("container_hints", "/etc/cadvisor/container_hints.json", "容器提示文件的位置")

type ContainerHints struct {
	AllHosts []containerHint `json:"all_hosts,omitempty"`
}

type containerHint struct {
	FullName         string            `json:"full_path,omitempty"`
	NetworkInterface *networkInterface `json:"network_interface,omitempty"`
	Mounts           []Mount           `json:"mounts,omitempty"`
}

type Mount struct {
	HostDir      string `json:"host_dir,omitempty"`
	ContainerDir string `json:"container_dir,omitempty"`
}

type networkInterface struct {
	VethHost  string `json:"veth_host,omitempty"`
	VethChild string `json:"veth_child,omitempty"`
}

func GetContainerHintsFromFile(containerHintsFile string) (ContainerHints, error) {
	dat, err := ioutil.ReadFile(containerHintsFile)
	if os.IsNotExist(err) {
		return ContainerHints{}, nil
	}
	var cHints ContainerHints
	if err == nil {
		err = json.Unmarshal(dat, &cHints)
	}

	return cHints, err
}
