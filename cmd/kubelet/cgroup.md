```
root@vm:/sys/fs/cgroup# cat cgroup.controllers 
cpuset cpu io memory hugetlb pids rdma misc
```


### cpuset 
用于将进程绑定到特定的 CPU 和内存节点上.它可以用于优化系统性能、减少资源竞争和避免 NUMA 效应等.