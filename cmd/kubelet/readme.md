- 
- 
- https://kubernetes.io/zh/docs/concepts/scheduling-eviction/node-pressure-eviction/






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
