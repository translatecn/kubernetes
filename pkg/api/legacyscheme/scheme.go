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

package legacyscheme

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	// Scheme 是runtime的默认实例。Kubernetes API中已经注册的类型的方案。
	// 如果你复制这个文件来创建一个新的api组，STOP!而是复制扩展组。这个Scheme是特殊的，应该只出现在api组中，除非你真的知道你在做什么。
	// TODO(lavalamp): make the above error impossible.
	Scheme = runtime.NewScheme()

	// Codecs 提供对这个 scheme 的编码和解码的访问
	Codecs = serializer.NewCodecFactory(Scheme)

	// ParameterCodec 处理转换为查询参数的对象的版本控制。
	ParameterCodec = runtime.NewParameterCodec(Scheme)
)
