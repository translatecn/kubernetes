#### kubelet给pod的状态
```
ContainersReady  PodConditionType = "ContainersReady"  // 指示 Pod 中的所有容器是否已经就绪。
PodInitialized   PodConditionType = "Initialized"      // 表示 Pod 中的所有 init 容器是否已经成功启动。
PodReady         PodConditionType = "Ready"            // 表示 Pod 是否能够服务请求，并且应该添加到所有匹配服务的负载均衡池中。
PodScheduled     PodConditionType = "PodScheduled"     // 表示此 Pod 的调度过程的状态。
# 需要开启 features.PodDisruptionConditions
DisruptionTarget PodConditionType = "DisruptionTarget" // 表示该 Pod 即将被终止，因为发生了某种干扰（例如抢占、逐出 API 或垃圾回收）。

# 需要开启 features.PodHasNetwork
PodHasNetwork = "PodHasNetwork"	// 表示已成功为pod配置网络并分配IP地址。在此条件为真之后，可以提取pod规范中指定的容器的映像，并启动容器。

```



#### pod的阶段
```
PodPending   PodPhase = "Pending"   // 表示该 Pod 已被系统接受，但一个或多个容器尚未启动。这包括绑定到节点之前的时间，以及在主机上拉取镜像的时间。
PodRunning   PodPhase = "Running"   // 表示该 Pod 已经绑定到节点，并且所有容器都已经启动。至少有一个容器仍在运行或正在重新启动过程中。
PodSucceeded PodPhase = "Succeeded" // 表示该 Pod 中的所有容器都已经自愿终止，并且系统不会重新启动这些容器。
PodFailed    PodPhase = "Failed"    // 表示该 Pod 中的所有容器都已经终止，并且至少有一个容器在失败中终止（以非零退出代码退出或被系统停止）。
PodUnknown   PodPhase = "Unknown"   // 表示由于某种原因无法获取 Pod 的状态，通常是由于与 Pod 所在主机通信时发生错误。
```