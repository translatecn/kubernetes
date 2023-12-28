package scheduler

import (
	"flag"
	"k8s.io/client-go/util/homedir"
	"os"
	"path/filepath"
	"runtime"
)

func Init(args []string) []string {
	kubeconfig := ""
	if home := homedir.HomeDir(); home != "" {
		flag.StringVar(&kubeconfig, "kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		flag.StringVar(&kubeconfig, "kubeconfig", "", "absolute path to the kubeconfig file")
	}

	name, _ := os.Hostname()
	if os.Getenv("DEBUG") != "" || name == "vm" || runtime.GOOS == `darwin` {

	} else {
		return args
	}

	args = append(args, "--authentication-kubeconfig="+kubeconfig)
	args = append(args, "--authorization-kubeconfig="+kubeconfig)
	args = append(args, "--bind-address=0.0.0.0")
	args = append(args, "--feature-gates=EphemeralContainers=true")
	args = append(args, "--kubeconfig="+kubeconfig)
	args = append(args, "--leader-elect=true")
	args = append(args, "--leader-elect-lease-duration=15s")
	args = append(args, "--leader-elect-renew-deadline=10s")
	args = append(args, "--leader-elect-resource-lock=leases")
	args = append(args, "--leader-elect-retry-period=2s")
	args = append(args, "--kube-api-qps=100")
	//args = append(args, "--write-config-to=/tmp/scheduler.conf")

	return args
}
