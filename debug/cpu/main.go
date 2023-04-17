package main

import (
	"fmt"
	"github.com/google/cadvisor/utils/cpuload/netlink"
	"time"
)

func main() {
	reader, _ := netlink.New()
	tick := time.Tick(time.Second)
	for _ = range tick {
		load, _ := reader.GetCpuLoad("/", "sys/fs/cgroup")
		fmt.Println(load)
	}
}
