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

package types

// NodeName 这段代码是一段注释，用于解释NodeName类型的含义和用途。NodeName类型用于保存api.Node的名称标识符，它是一个独立的类型，这有助于明确表示节点名称，避免与其他类似概念（主机名、云提供商ID、云提供商名称等）混淆。
//
// 为了澄清不同类型之间的区别，注释提供了以下信息：
//
// Node.Name是API中Node的Name字段。这应该存储在NodeName中。不幸的是，因为Name是ObjectMeta的一部分，我们无法在API级别将其存储为NodeName。
//
// Hostname是本地计算机的主机名（来自uname -n）。但是，一些组件允许用户传递--hostname-override标志，它将在大多数地方覆盖此主机名。在没有更有意义的内容的情况下，kubelet将使用Hostname作为创建Node时的Node.Name。
//
// 云提供商有他们自己的名称：GCE有InstanceName，AWS有InstanceId。对于GCE，InstanceName是GCE API中Instance对象的名称。在GCE上，Instance.Name变为Hostname，因此将其用作Node.Name也是有意义的。但这是GCE特定的，云提供商如何执行此映射取决于他们自己。
//
// 对于AWS，InstanceId尚不适合用作Node.Name，因此我们实际上使用PrivateDnsName作为Node.Name。这并不总是与主机名相同：如果我们使用自定义DHCP域，它将不同。
type NodeName string
