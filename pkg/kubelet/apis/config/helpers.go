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

package config

// KubeletConfigurationPathRefs 返回指向包含文件路径的所有KubeletConfiguration字段的指针。
// 例如,您可以使用此方法将所有相对路径解析为某些常见根路径,然后
// 将配置传递给应用程序。随着添加新字段,必须保持此方法的最新状态。
func KubeletConfigurationPathRefs(kc *KubeletConfiguration) []*string {
	paths := []*string{}
	paths = append(paths, &kc.StaticPodPath)
	paths = append(paths, &kc.Authentication.X509.ClientCAFile)
	paths = append(paths, &kc.TLSCertFile)
	paths = append(paths, &kc.TLSPrivateKeyFile)
	paths = append(paths, &kc.ResolverConfig)
	paths = append(paths, &kc.VolumePluginDir)
	return paths
}
