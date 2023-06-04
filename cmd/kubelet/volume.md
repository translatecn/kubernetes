#### PersistentVolumeClaim (PVC) 和 Ephemeral volume 都是 Kubernetes 中的卷,但它们有明显的区别：
   
    1. 生命周期：PVC 的生命周期与 Pod 是分开的,即使 Pod 被删除,PVC 中的数据也可以保存.而 Ephemeral volume 只能在 Pod 存在期间存在,当 Pod 删除后,Ephemeral volume 中的数据也会被删除.
    2. 使用场景：PVC 适用于需要持久化存储的应用场景,比如数据库.而 Ephemeral volume 适用于那些只需要在短时间内存在的应用场景,比如一次性任务.
    3. 配额申请方式：PVC 可以静态或动态配额申请,而 Ephemeral volume 只能通过动态配额申请来使用.
    4. 存储驱动：PVC 可以使用多种存储驱动来进行存储,而 Ephemeral volume 只能使用集群存储驱动进行存储.

    综上所述,PVC 适用于需要长期存储数据的应用场景,而 Ephemeral volume 适用于短暂存储数据的应用场景.




####    什么事-intree pv 和csi pv?
    
    in-tree pv是Kubernetes中早期的一种卷插件机制,它将卷插件直接内置在Kubernetes代码中.这些卷插件被编译到Kubernetes二进制文件中,并随着Kubernetes一起发布.
    in-tree pv支持多种类型的卷,如emptyDir、hostPath、NFS、GCEPersistentDisk等.但是,它的功能有限,不支持动态卷分配和许多高级功能.
    
    CSI pv是Kubernetes中的一种新型卷插件机制,它将卷插件实现为CSI驱动程序.CSI驱动程序是由存储供应商提供的独立二进制文件,它们与Kubernetes分开开发和部署.
    CSI pv支持动态卷分配、卷快照、卷克隆等高级功能,并且可以支持各种类型的存储后端,如AWS EBS、Azure Disk、Ceph、GlusterFS等.





syscall.ESTALE是一个系统调用错误码,表示文件句柄已经失效或过期.在网络文件系统中,如果文件句柄过期或不存在,就会返回这个错误码.



#### Attacher与Mounter的区别
    在 CSI 中,Attacher 插件负责将存储卷附加到节点上,然后调用 Mounter 插件将存储卷挂载到容器中.
    在 Kubernetes 中,Attacher 和 Mounter 是两个不同的组件,它们的作用分别是：
        - Attacher：用于将外部存储系统附加（attach）到节点上,以便在该节点上使用该存储系统.Attacher 通常是一个插件程序,用于实现特定的存储系统的附加逻辑,例如 AWS EBS、GCE PD、iSCSI、RBD 等.在 Kubernetes 中,Attacher 通常是 CSI（Container Storage Interface）插件的一部分,用于实现 CSI 中的 Node Service.
        - Mounter：用于将附加到节点上的存储系统挂载（mount）到容器中,以便在容器中使用该存储系统.Mounter 通常是 Kubernetes 中的一个内置组件,用于实现通用的挂载逻辑.在 Kubernetes 中,Mounter 通常是 kubelet 的一部分,用于实现 Pod 中的 Volume 挂载.
    因此,可以看出 Attacher 和 Mounter 的主要区别在于它们的作用范围不同：Attacher 的作用范围是节点级别,用于将存储系统附加到节点上；而 Mounter 的作用范围是容器级别,用于将存储系统挂载到容器中.在 Kubernetes 中,这两个组件通常是配合使用的,以实现存储系统的完整生命周期管理.


#### volume

    - Fibre Channel 是一种高速的、可靠的存储网络技术,通常用于连接存储设备和服务器.在 Kubernetes 中,如果需要使用 Fibre Channel 存储系统作为持久化卷,就需要使用 fcAttacher 插件将其附加到节点上,并使用其他 CSI 组件（如 Controller 和 Node Plugin）配合实现持久化卷的管理和挂载.
    - FlexVolume 是 Kubernetes 中的一种存储插件框架,用于支持各种不同的存储系统,包括云存储、网络存储和本地存储等.FlexVolume 支持动态加载和卸载存储插件,因此可以根据需要灵活地选择不同的存储系统.




filesystem类型的volume位置就是pod目录下 volume文件夹 , 3种插件类型的volume
```
[root@k8s-node01 volumes]# ll /var/lib/kubelet/pods/737188e1-d5ac-4c1f-8350-a39a60723e85/volumes
total 4
drwxr-xr-x 26 root root 4096 Sep  6 12:36 kubernetes.io~configmap
drwxr-xr-x  3 root root   29 Sep  6 12:36 kubernetes.io~empty-dir
drwxr-xr-x  4 root root   60 Sep  6 12:36 kubernetes.io~secret

```



#### block volume
- 在容器内显示为设备





#### rootfs 挂载点
- /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs