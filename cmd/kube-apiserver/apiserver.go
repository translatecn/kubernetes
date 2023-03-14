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

// apiserver is the main api server and master for the cluster.
// it is responsible for serving the cluster management API.
package main

import (
	"os"
	"strings"
	_ "time/tzdata" // for timeZone support in CronJob

	"k8s.io/component-base/cli"
	_ "k8s.io/component-base/logs/json/register"          // for JSON log format registration
	_ "k8s.io/component-base/metrics/prometheus/clientgo" // load all the prometheus client-go plugins
	_ "k8s.io/component-base/metrics/prometheus/version"  // for version metric registration
	"k8s.io/kubernetes/cmd/kube-apiserver/app"
)

func main() {
	args := `--advertise-address=192.168.33.101 --allow-privileged=true
	--audit-log-format=json --audit-log-maxage=7 --audit-log-maxbackup=10
	--audit-log-maxsize=100 --audit-log-path=/var/log/kubernetes/audit.log
	--audit-policy-file=/etc/kubernetes/audit-policy.yml --authorization-mode=Node,RBAC
	--client-ca-file=/etc/kubernetes/pki/ca.crt --enable-admission-plugins=NodeRestriction
	--enable-aggregator-routing=true --enable-bootstrap-token-auth=true
	--etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt
	--etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt
	--etcd-keyfile=/etc/kubernetes/pki/apiserver-etcd-client.key
	--etcd-servers=https://127.0.0.1:2379 --feature-gates=EphemeralContainers=true
	--kubelet-client-certificate=/etc/kubernetes/pki/apiserver-kubelet-client.crt
	--kubelet-client-key=/etc/kubernetes/pki/apiserver-kubelet-client.key
	--kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname
	--proxy-client-cert-file=/etc/kubernetes/pki/front-proxy-client.crt
	--proxy-client-key-file=/etc/kubernetes/pki/front-proxy-client.key
	--requestheader-allowed-names=front-proxy-client
	--requestheader-client-ca-file=/etc/kubernetes/pki/front-proxy-ca.crt
	--requestheader-extra-headers-prefix=X-Remote-Extra- --requestheader-group-headers=X-Remote-Group
	--requestheader-username-headers=X-Remote-User
	--secure-port=16443
	--service-account-issuer=https://kubernetes.default.svc.cluster.local
	--service-account-key-file=/etc/kubernetes/pki/sa.pub
	--service-account-signing-key-file=/etc/kubernetes/pki/sa.key
	--service-cluster-ip-range=10.96.0.0/22
	--tls-cert-file=/etc/kubernetes/pki/apiserver.crt
	--tls-private-key-file=/etc/kubernetes/pki/apiserver.key`

	for _, v := range strings.Split(strings.Replace(args, "\t\n", " ", -1), " ") {
		os.Args = append(os.Args, v)
	}
	command := app.NewAPIServerCommand()
	code := cli.Run(command)
	os.Exit(code)
}
