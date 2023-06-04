```
kubepods/：用于限制 Pod 的 CPU 和内存资源使用量.

kubelet/：用于限制 Kubelet 本身的 CPU 和内存资源使用量.

system.slice/：用于限制节点上其他系统进程的 CPU 和内存资源使用量.
```


--kube-reserved：用于设置 Kubernetes 系统保留资源的数量.
--system-reserved：用于设置系统保留资源的数量.
--kube-reserved-cgroup：用于设置用于限制 Kubernetes 系统保留资源的 Cgroup 名称.
--system-reserved-cgroup：用于设置用于限制系统保留资源的 Cgroup 名称.
--enforce-node-allocatable：用于启用或禁用节点可分配资源的强制执行.
--eviction-hard：用于设置硬驱逐阈值列表,以控制 Pod 的驱逐行为.