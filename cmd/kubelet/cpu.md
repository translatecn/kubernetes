https://zhuanlan.zhihu.com/p/557369339
https://zhuanlan.zhihu.com/p/547697542
https://kubernetes.io/zh-cn/blog/2023/06/09/dl-adopt-cdn/


## 以大白话来解释,"align-by-socket"和"single-numa-node"之间的冲突是因为它们在CPU分配时采取了不同的策略.
```
"align-by-socket"的意思是将CPU视为在套接字边界上对齐.套接字是一个物理组件,它包含多个CPU核心和内存控制器.这意味着当使用"align-by-socket"时,容器的CPU将在套接字边界上分配,以便更好地利用套接字的资源.

而"single-numa-node"的意思是将CPU视为在NUMA边界上对齐.NUMA（非一致性存储访问）是一种计算机内存访问的方式,其中内存被分割成多个区域,并且每个区域与特定的处理器核心相关联.
使用"single-numa-node"时,容器的CPU将在NUMA边界上分配,以确保每个容器都在一个NUMA节点上运行,从而提高性能.

由于"align-by-socket"和"single-numa-node"采取了不同的策略,它们的限制条件可能会相互冲突,因此在某些情况下,无法同时使用这两个标志.这可能会导致容器无法正确地分配CPU资源,从而影响性能或导致其他问题.






```
## 什么时候会发生冲突
```
冲突可能会发生在具有特定硬件配置的系统上.下面是一些可能导致"align-by-socket"和"single-numa-node"冲突的情况：

1. 单套接字多NUMA节点：在某些系统中,一个套接字可能包含多个NUMA节点.这种情况下,如果同时启用"align-by-socket"和"single-numa-node",则会发生冲突,因为一个容器无法同时在一个套接字和一个NUMA节点上运行.

2. 非对称的套接字和NUMA节点：在某些系统中,套接字和NUMA节点的数量可能不对称.例如,一个套接字可能包含多个NUMA节点,或者一个NUMA节点可能跨越多个套接字.在这种情况下,"align-by-socket"和"single-numa-node"可能无法同时满足,因为容器无法在套接字和NUMA节点之间进行完美的对齐.

3. 其他分配策略限制：除了"align-by-socket"和"single-numa-node"之外,可能还有其他的CPU分配策略限制.这些策略可能与特定的硬件和操作系统相关,并且可能与"align-by-socket"和"single-numa-node"冲突.

在这些情况下,可能需要根据具体的需求和硬件配置来选择使用哪个标志,或者找到其他的解决方案来避免冲突.
```



