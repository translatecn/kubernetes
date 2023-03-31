package kubelet

import "os"

func Init(args []string) []string {
	if os.Getenv("DEBUG") == "" {
		return args
	}
	args = append(args, "--address=172.20.53.123")
	args = append(args, "--anonymous-auth=false")
	args = append(args, "--feature-gates=DisableAcceleratorUsageMetrics=true")
	args = append(args, "--authentication-token-webhook")
	args = append(args, "--authorization-mode=Webhook")
	args = append(args, "--client-ca-file=/etc/kubernetes/ssl/ca.pem")
	args = append(args, "--cluster-dns=10.68.0.2")
	args = append(args, "--cluster-domain=cluster.local.")
	args = append(args, "--cni-bin-dir=/usr/bin")
	args = append(args, "--cni-conf-dir=/etc/cni/net.d")
	args = append(args, "--fail-swap-on=false")
	args = append(args, "--hairpin-mode hairpin-veth")
	args = append(args, "--hostname-override=172.20.53.123")
	args = append(args, "--image-pull-progress-deadline=30m")
	args = append(args, "--kubeconfig=/etc/kubernetes/kubelet.kubeconfig")
	args = append(args, "--max-pods=110")
	args = append(args, "--network-plugin=cni")
	args = append(args, "--pod-infra-container-image=registry.datacanvas.com:5000/dc/service/k8s/kube-pause-amd64:3.1")
	args = append(args, "--register-node=true")
	args = append(args, "--root-dir=/var/lib/kubelet")
	args = append(args, "--tls-cert-file=/etc/kubernetes/ssl/kubelet.pem")
	args = append(args, "--tls-private-key-file=/etc/kubernetes/ssl/kubelet-key.pem")
	args = append(args, "--feature-gates=DevicePlugins=true")
	args = append(args, "--cgroup-driver=systemd")
	args = append(args, "--enforce-node-allocatable=pods,kube-reserved")
	args = append(args, "--kube-reserved=cpu=4,memory=16Gi")
	args = append(args, "--kube-reserved-cgroup=/runtime")
	args = append(args, "--v=2")

	return args
}
