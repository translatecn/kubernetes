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

// The kubelet binary is responsible for maintaining a set of containers on a particular host VM.
// It syncs data from both configuration file(s) as well as from a quorum of etcd servers.
// It then communicates with the contatype DesiredStateOfWorld interface {iner runtime (or a CRI shim for the runtime) to see what is
// currently running.  It synchronizes the configuration data, with the running set of containers
// by starting or stopping containers.
package main

import (
	"k8s.io/kubernetes/debug/kubelet"
	"os"

	"k8s.io/component-base/cli"
	_ "k8s.io/component-base/logs/json/register" // for JSON log format registration
	_ "k8s.io/component-base/metrics/prometheus/restclient"
	_ "k8s.io/component-base/metrics/prometheus/version" // for version metric registration
	"k8s.io/kubernetes/cmd/kubelet/app"
)

func main() {
	// InstallDefaultHandlers() {
	// AddKubeletConfigFlags
	// func (f *KubeletFlags) AddFlags(mainfs *pflag.FlagSet) {

	// curl -k --key /etc/kubernetes/pki/apiserver-kubelet-client.key --cert /etc/kubernetes/pki/apiserver-kubelet-client.crt --cacert /etc/kubernetes/pki/ca.crt https://127.0.0.1:10250/pods
	// curl -k --key /etc/kubernetes/pki/apiserver-kubelet-client.key --cert /etc/kubernetes/pki/apiserver-kubelet-client.crt --cacert /etc/kubernetes/pki/ca.crt https://127.0.0.1:10250/metrics/resource

	// export TOKEN=$(cat /run/secrets/kubernetes.io/serviceaccount/token)
	// curl -k -s --cacert /run/secrets/kubernetes.io/serviceaccount/ca.crt --header "Authorization: Bearer $TOKEN"  http://10.96.181.196:10250/stats/summary   |python -m json.tool

	os.Args = kubelet.Init(os.Args)
	// --bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf --config=/var/lib/kubelet/config.yaml --container-runtime-endpoint=unix:///run/containerd/containerd.sock --pod-infra-container-image=registry.k8s.io/pause:3.9 --container-runtime=remote --pod-infra-container-image=sealos.hub:5000/pause:3.9 --runtime-request-timeout=15m --container-runtime-endpoint=unix:///var/run/containerd/containerd.sock --image-service-endpoint=unix:///var/run/image-cri-shim.sock
	command := app.NewKubeletCommand()
	code := cli.Run(command)
	os.Exit(code)
}
