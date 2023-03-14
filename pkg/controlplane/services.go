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

package controlplane

import (
	"fmt"
	"net"

	"k8s.io/klog/v2"
	"k8s.io/utils/integer"
	utilnet "k8s.io/utils/net"

	kubeoptions "k8s.io/kubernetes/pkg/kubeapiserver/options"
)

// ServiceIPRange 检查serviceClusterIPRange标志是否为nil，如果是，则发出警告，并将服务ip范围设置为kubeoptions中的默认值。
// DefaultServiceIPCIDR，直到根据弃用时间轴指南删除默认值。返回服务ip范围、api服务器服务ip和一个错误
func ServiceIPRange(passedServiceClusterIPRange net.IPNet) (net.IPNet, net.IP, error) {
	serviceClusterIPRange := passedServiceClusterIPRange
	if passedServiceClusterIPRange.IP == nil {
		klog.Warningf("未指定业务集群ip的CIDR。默认值%s已弃用，将在未来的版本中删除。请在kube-apiserver上使用--service-cluster-ip-range指定。\n ", kubeoptions.DefaultServiceIPCIDR.String())
		serviceClusterIPRange = kubeoptions.DefaultServiceIPCIDR
	}

	size := integer.Int64Min(utilnet.RangeSize(&serviceClusterIPRange), 1<<16)
	if size < 8 {
		return net.IPNet{}, net.IP{}, fmt.Errorf("the service cluster IP range must be at least %d IP addresses", 8)
	}

	// 从ServiceClusterIPRange中选择第一个有效IP作为GenericAPIServer服务IP。
	apiServerServiceIP, err := utilnet.GetIndexedIP(&serviceClusterIPRange, 1)
	if err != nil {
		return net.IPNet{}, net.IP{}, err
	}
	klog.V(4).Infof("Setting service IP to %q (read-write).", apiServerServiceIP)

	return serviceClusterIPRange, apiServerServiceIP, nil
}
