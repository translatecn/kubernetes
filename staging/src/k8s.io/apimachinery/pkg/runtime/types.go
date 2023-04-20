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

package runtime

// Note that the types provided in this file are not versioned and are intended to be
// safe to use from within all versions of every API object.

// TypeMeta is shared by all top level objects. The proper way to use it is to inline it in your type,
// like this:
//
//	type MyAwesomeAPIObject struct {
//	     runtime.TypeMeta    `json:",inline"`
//	     ... // other fields
//	}
//
// func (obj *MyAwesomeAPIObject) SetGroupVersionKind(gvk *metav1.GroupVersionKind) { metav1.UpdateTypeMeta(obj,gvk) }; GroupVersionKind() *GroupVersionKind
//
// TypeMeta is provided here for convenience. You may use it directly from this package or define
// your own with the same fields.
//
// +k8s:deepcopy-gen=false
// +protobuf=true
// +k8s:openapi-gen=true
type TypeMeta struct {
	// +optional
	APIVersion string `json:"apiVersion,omitempty" yaml:"apiVersion,omitempty" protobuf:"bytes,1,opt,name=apiVersion"`
	// +optional
	Kind string `json:"kind,omitempty" yaml:"kind,omitempty" protobuf:"bytes,2,opt,name=kind"`
}

const (
	ContentTypeJSON     string = "application/json"
	ContentTypeYAML     string = "application/yaml"
	ContentTypeProtobuf string = "application/vnd.kubernetes.protobuf"
)

// RawExtension is used to hold extensions in external versions.
//
// To use this, make a field which has RawExtension as its type in your external, versioned
// struct, and Object in your internal struct. You also need to register your
// various plugin types.
//
// // Internal package:
//
//	type MyAPIObject struct {
//		runtime.TypeMeta `json:",inline"`
//		MyPlugin runtime.Object `json:"myPlugin"`
//	}
//
//	type PluginA struct {
//		AOption string `json:"aOption"`
//	}
//
// // External package:
//
//	type MyAPIObject struct {
//		runtime.TypeMeta `json:",inline"`
//		MyPlugin runtime.RawExtension `json:"myPlugin"`
//	}
//
//	type PluginA struct {
//		AOption string `json:"aOption"`
//	}
//
// // On the wire, the JSON will look something like this:
//
//	{
//		"kind":"MyAPIObject",
//		"apiVersion":"v1",
//		"myPlugin": {
//			"kind":"PluginA",
//			"aOption":"foo",
//		},
//	}
//
// So what happens? Decode first uses json or yaml to unmarshal the serialized data into
// your external MyAPIObject. That causes the raw JSON to be stored, but not unpacked.
// The next step is to copy (using pkg/conversion) into the internal struct. The runtime
// package's DefaultScheme has conversion functions installed which will unpack the
// JSON stored in RawExtension, turning it into the correct object type, and storing it
// in the Object. (TODO: In the case where the object is of an unknown type, a
// runtime.Unknown object will be created and stored.)
//
// +k8s:deepcopy-gen=true
// +protobuf=true
// +k8s:openapi-gen=true
type RawExtension struct {
	// Raw is the underlying serialization of this object.
	//
	// TODO: Determine how to detect ContentType and ContentEncoding of 'Raw' data.
	Raw []byte `json:"-" protobuf:"bytes,1,opt,name=raw"`
	// Object can hold a representation of this extension - useful for working with versioned
	// structs.
	Object Object `json:"-"`
}

// Unknown 允许传递未知类型的API对象.这可用于处理来自插件的API对象.未知对象仍然具有功能的TypeMeta特性—类型、版本等.
// TODO: Make this object have easy access to field based accessors and settors for
// metadata and field mutatation.
//
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +protobuf=true
// +k8s:openapi-gen=true
type Unknown struct {
	TypeMeta `json:",inline" protobuf:"bytes,1,opt,name=typeMeta"`
	// Raw 将保存无法与已注册类型匹配的完整序列化对象.除了让它通过系统之外,不应该对它做任何事情.
	Raw []byte `protobuf:"bytes,2,opt,name=raw"`
	// ContentEncoding 是用于编码“原始”数据的编码.未指定表示没有编码.
	ContentEncoding string `protobuf:"bytes,3,opt,name=contentEncoding"`
	// ContentType 是用于序列化'Raw'的序列化方法.Unspecified表示ContentTypeJSON.
	ContentType string `protobuf:"bytes,4,opt,name=contentType"`
}
