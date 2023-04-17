- 
- 
- https://kubernetes.io/zh/docs/concepts/scheduling-eviction/node-pressure-eviction/
- http://man7.org/linux/man-pages/man5/proc.5.html


- cat /proc/self/mountinfo
- ls /sys/kernel/mm/hugepages
- ls /dev/disk/by-uuid
- df /
- cat /proc/cpuinfo
- cat /proc/meminfo
- ls /sys/devices/system/edac/mc/
- cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
- cat /proc/diskstats
- ls /sys/block
- cat /sys/block/sda/dev
- cat /sys/block/sda/size
- cat /sys/block/sda/queue/scheduler
- ls /sys/class/net
- cat /sys/class/net/enp0s5/address
- cat /sys/class/net/enp0s5/mtu
- cat /sys/class/net/enp0s5/speed
- cat /sys/devices/system/node/node0/cpu0/topology/core_id


#### SystemUUID
```
/sys/class/dmi/id/product_uuid
/proc/device-tree/system-id
/proc/device-tree/vm,uuid
/etc/machine-id
```
#### MachineID
```
cat /etc/machine-id 
cat /var/lib/dbus/machine-id 
```
#### BootID
```
cat /proc/sys/kernel/random/boot_id 
```


#### 什么是MirrorPod
```
MirrorPod是Kubernetes中的一个概念，用于在节点上创建一个镜像Pod，以便在节点上缓存Pod的镜像，从而提高Pod的启动速度和可靠性。MirrorPod是由kubelet代理创建的，它与原始Pod具有相同的规范，但不会运行容器。MirrorPod只包含容器镜像和元数据，不包含容器的状态或运行时信息。
当kubelet代理检测到Pod需要在节点上启动时，它会首先尝试使用MirrorPod来启动容器。如果MirrorPod不存在或不可用，则kubelet将从容器镜像库中拉取容器镜像，并启动容器。使用MirrorPod可以避免在每次启动Pod时都需要拉取镜像的延迟和网络带宽消耗，从而提高Pod的启动速度和可靠性。
需要注意的是，MirrorPod是由kubelet代理创建和管理的，用户不能直接操作MirrorPod。MirrorPod的生命周期与kubelet代理的生命周期相同，当kubelet代理停止时，MirrorPod也将被删除。
```


#### QOS

``` 
BestEffort（优先级最低）
Burstable
Guaranteed（优先级最高）
```

#### rootfs 与 imagefs的区别
```
在 Kubernetes 中，rootfs 和 imagefs 是指容器的两个不同的文件系统。
rootfs 是容器的根文件系统，是容器中所有文件和目录的基础。它通常是一个只读的文件系统，其中包含了容器镜像的基本文件和目录结构。
imagefs 是容器镜像中的文件系统，包含了容器运行时所需的所有文件和目录。当容器启动时，imagefs 中的文件系统会被挂载到 rootfs 上，形成容器的完整文件系统。
```

#### GetOwnCgroupPath
```
// 避免在cgroup v2上使用GetOwnCgroupPath，因为它不受libcontainer支持。
//
//cgroup是Linux内核中的一个特性，用于限制和隔离进程的资源使用。cgroup有两个版本，即cgroup v1和cgroup v2。在cgroup v1中，
//每个进程都有自己的cgroup路径，可以使用GetOwnCgroupPath函数来获取它的路径。但是，在cgroup v2中，每个进程的cgroup路径是动态生成的，无法使用GetOwnCgroupPath函数来获取它的路径。
//
//因此，如果在cgroup v2上使用GetOwnCgroupPath函数，可能会导致错误或不可预测的结果。为了避免这种情况，建议在cgroup v2上使用其他函数或工具来获取进程的cgroup路径，或者使用cgroup v1来进行进程隔离。
```


#### cgroup v2  unified\hybrid
```
cgroup v2有两种模式：统一模式（unified mode）和混合模式（hybrid mode）。

统一模式是cgroup v2的默认模式。在统一模式下，所有的cgroup子系统都被组合成一个单一的层次结构，每个进程只有一个cgroup路径。在这种模式下，可以使用cgroup v2的新特性，例如动态生成路径和递归删除等。

混合模式是cgroup v2的一种可选模式。在混合模式下，cgroup v2与cgroup v1共存，每个进程有两个cgroup路径。在这种模式下，可以在不影响cgroup v1的情况下使用cgroup v2的新特性。

在统一模式下，cgroup v2子系统的挂载点是/sys/fs/cgroup，而在混合模式下，cgroup v2子系统的挂载点是/sys/fs/cgroup/unified，cgroup v1子系统的挂载点是/sys/fs/cgroup/systemd。

需要注意的是，不同的Linux发行版和内核版本可能对cgroup v2的支持程度有所不同，因此在使用cgroup v2时需要仔细评估和测试。
```


#### devicemapper
```
devicemapper 是Docker使用的一种存储驱动程序，它使用设备映射技术将容器文件系统映射到主机文件系统中。
在使用devicemapper时，容器的挂载点通常位于/dev/mapper目录下，例如/dev/mapper/docker-xxx。由于devicemapper使用的是块设备，因此在容器挂载时可能会出现一些问题，例如性能下降、挂载失败等等。

为了避免这些问题，建议避免在devicemapper上挂载容器，并使用ThinPoolWatcher来跟踪devicemapper的使用情况。
ThinPoolWatcher是一个Docker守护程序，用于监视devicemapper的Thin Pool使用情况，并在空间不足时触发警报或自动清理操作。通过使用ThinPoolWatcher，可以避免devicemapper的空间问题，并确保容器的稳定性和可靠性。

需要注意的是，devicemapper已经不再是Docker的推荐存储驱动程序，建议使用更先进的存储技术，例如overlay2或btrfs。
```


#### hugepage_nr
```
hugepage_nr 是一个Linux内核参数，用于指定系统中Huge Pages的数量。

Huge Pages是一种特殊的内存页面，它的大小通常为2MB或1GB，比普通的页面要大得多。Huge Pages通常用于需要大量内存的应用程序，例如数据库、虚拟机等等。由于Huge Pages的大小比普通页面大，因此可以减少内存碎片和TLB缓存的使用，从而提高应用程序的性能和可靠性。

在Linux系统中，可以使用hugepage_nr参数来指定系统中Huge Pages的数量。该参数通常位于/proc/sys/vm目录下，可以使用以下命令来查看或修改它的值：

$ cat /proc/sys/vm/hugepage_nr
$ echo N > /proc/sys/vm/hugepage_nr

其中，N为Huge Pages的数量。需要注意的是，修改hugepage_nr参数的值可能需要root权限，并且可能会影响系统的性能和稳定性。因此，在修改该参数之前，需要仔细评估和测试系统的性能和稳定性。
```


#### inotify_init
```
fd, errno := syscall.InotifyInit1(syscall.IN_CLOEXEC)

inotify是Linux内核提供的一种机制，用于监视文件系统事件。通过inotify，应用程序可以实时监视文件或目录的创建、修改、删除等事件，并在事件发生时进行相应的处理。
inotify_init 系统调用可以创建一个inotify实例，并返回一个文件描述符，该文件描述符可以用于监视文件系统事件。
```





#### oom
```
6,727,35945901675,-;oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),
cpuset=cri-containerd-f69706726f784bfb90a8a6378a41d684f1ed23508ef32ba586e477509f121867.scope,mems_allowed=0,
oom_memcg=/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod233b806c_04ce_433c_9e64_cf4c323e6c16.slice,
task_memcg=/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod233b806c_04ce_433c_9e64_cf4c323e6c16.slice/cri-containerd-f69706726f784bfb90a8a6378a41d684f1ed23508ef32ba586e477509f121867.scope,
task=python,pid=988370,uid=0


3,728,35945901683,-;Memory cgroup out of memory: Killed process 988370 (python) total-vm:9783776kB, anon-rss:95724kB, file-rss:3268kB, shmem-rss:0kB, UID:0 pgtables:240kB oom_score_adj:995

```





# ToDo
- registerCollectors