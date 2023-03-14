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
	"fmt"
	"k8s.io/kubernetes/debug/utils"
	"os"
	_ "time/tzdata" // for timeZone support in CronJob

	"k8s.io/component-base/cli"
	_ "k8s.io/component-base/logs/json/register"          // for JSON log format registration
	_ "k8s.io/component-base/metrics/prometheus/clientgo" // load all the prometheus client-go plugins
	_ "k8s.io/component-base/metrics/prometheus/version"  // for version metric registration
	"k8s.io/kubernetes/cmd/kube-apiserver/app"
)

func main() {
	os.Args = append(os.Args, fmt.Sprintf("--advertise-address=%s", utils.GetOutBoundIP()))
	os.Args = append(os.Args, "--allow-privileged=true")
	os.Args = append(os.Args, "--audit-log-format=json")
	os.Args = append(os.Args, "--audit-log-maxage=7")
	os.Args = append(os.Args, "--audit-log-maxbackup=10")
	os.Args = append(os.Args, "--audit-log-maxsize=100")
	//os.Args = append(os.Args, "--audit-log-path=/tmp/audit.log")
	//os.Args = append(os.Args, "--audit-policy-file=/tmp/kubernetes/audit-policy.yml")
	os.Args = append(os.Args, "--authorization-mode=Node,RBAC")
	//os.Args = append(os.Args, "--client-ca-file=/tmp/kubernetes/pki/ca.crt")
	os.Args = append(os.Args, "--enable-admission-plugins=NodeRestriction")
	os.Args = append(os.Args, "--enable-aggregator-routing=true")
	os.Args = append(os.Args, "--enable-bootstrap-token-auth=true")
	//os.Args = append(os.Args, "--etcd-cafile=/tmp/kubernetes/pki/etcd/ca.crt")
	//os.Args = append(os.Args, "--etcd-certfile=/tmp/kubernetes/pki/apiserver-etcd-client.crt")
	//os.Args = append(os.Args, "--etcd-keyfile=/tmp/kubernetes/pki/apiserver-etcd-client.key")
	os.Args = append(os.Args, "--etcd-servers=https://127.0.0.1:2379")
	os.Args = append(os.Args, "--feature-gates=EphemeralContainers=true")
	//os.Args = append(os.Args, "--kubelet-client-certificate=/tmp/kubernetes/pki/apiserver-kubelet-client.crt")
	//os.Args = append(os.Args, "--kubelet-client-key=/tmp/kubernetes/pki/apiserver-kubelet-client.key")
	os.Args = append(os.Args, "--kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname")
	//os.Args = append(os.Args, "--proxy-client-cert-file=/tmp/kubernetes/pki/front-proxy-client.crt")
	//os.Args = append(os.Args, "--proxy-client-key-file=/tmp/kubernetes/pki/front-proxy-client.key")
	os.Args = append(os.Args, "--requestheader-allowed-names=front-proxy-client")
	//os.Args = append(os.Args, "--requestheader-client-ca-file=/tmp/kubernetes/pki/front-proxy-ca.crt")
	os.Args = append(os.Args, "--requestheader-extra-headers-prefix=X-Remote-Extra-")
	os.Args = append(os.Args, "--requestheader-group-headers=X-Remote-Group")
	os.Args = append(os.Args, "--requestheader-username-headers=X-Remote-User")
	os.Args = append(os.Args, "--secure-port=6443")
	os.Args = append(os.Args, "--service-account-issuer=https://kubernetes.default.svc.cluster.local")
	//os.Args = append(os.Args, "--service-account-key-file=/tmp/kubernetes/pki/sa.pub")
	//os.Args = append(os.Args, "--service-account-signing-key-file=/tmp/kubernetes/pki/sa.key")
	os.Args = append(os.Args, "--service-cluster-ip-range=10.96.0.0/22")
	//os.Args = append(os.Args, "--tls-cert-file=/tmp/kubernetes/pki/apiserver.crt")
	//os.Args = append(os.Args, "--tls-private-key-file=/tmp/kubernetes/pki/apiserver.key")
	command := app.NewAPIServerCommand()
	code := cli.Run(command)
	os.Exit(code)
}
