#### GenericPLEG和EventedPLEG的区别
```


在 Kubernetes 中,PLEG 是 Pod Lifecycle Event Generator 的缩写,用于生成有关 Pod 生命周期事件的信息.PLEG 有两种实现方式：GenericPLEG 和 EventedPLEG.


GenericPLEG 是 Kubernetes 1.0 中引入的默认实现.它使用轮询机制来监视容器的状态,并生成有关 Pod 生命周期事件的信息.GenericPLEG 的缺点是它会占用大量的 CPU 资源,并且在大型集群中可能会导致延迟.


EventedPLEG 是 Kubernetes 1.6 中引入的新实现.它使用事件驱动机制来监视容器的状态,并生成有关 Pod 生命周期事件的信息.EventedPLEG 的优点是它使用的资源更少,并且在大型集群中表现更好.另外,EventedPLEG 还支持 PodSandboxStatus 和 ContainerStatus 的事件通知,以便更好地监视容器的状态.


因此,GenericPLEG 和 EventedPLEG 的主要区别在于它们的实现方式.GenericPLEG 使用轮询机制来监视容器的状态,而 EventedPLEG 使用事件驱动机制来监视容器的状态.EventedPLEG 的性能更好,并且支持更多的事件通知.


```
