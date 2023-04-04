package kubelet

import "os"

func Init(args []string) []string {
	if os.Getenv("DEBUG") == "" {
		return args
	}
	args = append(args, "--bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf")
	args = append(args, "--kubeconfig=/etc/kubernetes/kubelet.conf")
	args = append(args, "--config=/var/lib/kubelet/config.yaml")
	args = append(args, "--port=20001")
	args = append(args, "--healthz-port=20002")
	args = append(args, "--container-runtime-endpoint=unix:///run/containerd/containerd.sock")
	args = append(args, "--pod-infra-container-image=registry.k8s.io/pause:3.9")
	args = append(args, "--pod-infra-container-image=sealos.hub:5000/pause:3.9")
	args = append(args, "--container-runtime=remote")
	args = append(args, "--runtime-request-timeout=15m")
	args = append(args, "--container-runtime-endpoint=unix:///run/containerd/containerd.sock")
	args = append(args, "--image-service-endpoint=unix:///var/run/image-cri-shim.sock")
	return args
}
