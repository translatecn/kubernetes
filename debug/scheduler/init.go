package scheduler

import "os"

func Init(args []string) []string {
	name, _ := os.Hostname()
	if os.Getenv("DEBUG") != "" || name == "vm" {
	} else {
		return args
	}

	args = append(args, "--authentication-kubeconfig=/etc/kubernetes/scheduler.conf")
	args = append(args, "--authorization-kubeconfig=/etc/kubernetes/scheduler.conf")
	args = append(args, "--bind-address=0.0.0.0")
	args = append(args, "--feature-gates=EphemeralContainers=true")
	args = append(args, "--kubeconfig=/etc/kubernetes/scheduler.conf")
	args = append(args, "--leader-elect=true")
	return args
}
