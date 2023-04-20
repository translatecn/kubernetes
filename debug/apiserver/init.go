package apiserver

import "os"

func Init(args []string) []string {
	name, _ := os.Hostname()
	if os.Getenv("DEBUG") != "" || name == "vm" {
		if os.Getenv("SKIP") != "" {
			return args
		}
	} else {
		return args
	}
	args = append(args, "--advertise-address=192.168.33.9")
	args = append(args, "--allow-privileged=true")
	args = append(args, "--audit-log-format=json")
	args = append(args, "--audit-log-maxage=7")
	args = append(args, "--audit-log-maxbackup=10")
	args = append(args, "--audit-log-maxsize=100")
	args = append(args, "--audit-log-path=/var/log/kubernetes/audit.log2")
	args = append(args, "--audit-policy-file=/etc/kubernetes/audit-policy.yml")

	args = append(args, "--authorization-mode=Node,RBAC")

	args = append(args, "--client-ca-file=/etc/kubernetes/pki/ca.crt")
	args = append(args, "--enable-admission-plugins=NodeRestriction")
	args = append(args, "--enable-aggregator-routing=true")
	args = append(args, "--enable-bootstrap-token-auth=true")

	args = append(args, "--etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt")
	args = append(args, "--etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt")
	args = append(args, "--etcd-keyfile=/etc/kubernetes/pki/apiserver-etcd-client.key")
	args = append(args, "--etcd-servers=https://127.0.0.1:2379")

	args = append(args, "--feature-gates=EphemeralContainers=true")

	args = append(args, "--kubelet-client-certificate=/etc/kubernetes/pki/apiserver-kubelet-client.crt")
	args = append(args, "--kubelet-client-key=/etc/kubernetes/pki/apiserver-kubelet-client.key")
	args = append(args, "--kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname")
	args = append(args, "--proxy-client-cert-file=/etc/kubernetes/pki/front-proxy-client.crt")
	args = append(args, "--proxy-client-key-file=/etc/kubernetes/pki/front-proxy-client.key")

	args = append(args, "--requestheader-client-ca-file=/etc/kubernetes/pki/front-proxy-ca.crt")
	args = append(args, "--requestheader-allowed-names=front-proxy-client")
	args = append(args, "--requestheader-extra-headers-prefix=X-Remote-Extra-")
	args = append(args, "--requestheader-group-headers=X-Remote-Group")
	args = append(args, "--requestheader-username-headers=X-Remote-User")

	args = append(args, "--secure-port=16443")
	args = append(args, "--service-account-issuer=https://kubernetes.default.svc.cluster.local")
	args = append(args, "--service-account-key-file=/etc/kubernetes/pki/sa.pub")
	args = append(args, "--service-account-signing-key-file=/etc/kubernetes/pki/sa.key")
	args = append(args, "--service-cluster-ip-range=10.96.0.0/22")
	args = append(args, "--tls-cert-file=/etc/kubernetes/pki/apiserver.crt")
	args = append(args, "--tls-private-key-file=/etc/kubernetes/pki/apiserver.key")

	return args
}
