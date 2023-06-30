https://blog.csdn.net/qq_43684922/article/details/128721400
https://zhuanlan.zhihu.com/p/387617363
https://zhuanlan.zhihu.com/p/128677316
https://blog.csdn.net/qq_23662505/article/details/123689861
https://www.cnblogs.com/zphj1987/p/13575353.html
https://blog.csdn.net/ver_mouth__/article/details/125265751
https://mp.weixin.qq.com/s/CdqJ0X9IqiFnZMETNOWZqw
 

apt install numactl -y && numactl --hardware

```
[root@node01 ~]# numactl --hardware
available: 2 nodes (0-1)   一共40逻辑核,两个CPU
node 0 cpus: 0 2 4 6 8 10 12 14 16 18 20 22 24 26 28 30 32 34 36 38   
node 0 size: 128671 MB
node 0 free: 44691 MB
node 1 cpus: 1 3 5 7 9 11 13 15 17 19 21 23 25 27 29 31 33 35 37 39
node 1 size: 129020 MB
node 1 free: 42542 MB
node distances:             #表示跨node之间的距离,这里表示跨node之间访问成本是本node之内访问成本的2倍
node   0   1   
  0:  10  21 
  1:  21  10 
  
  
```
  
  
  
### cpu 
```
[root@node01 cpu]# ls /sys/devices/system/node/node0/c
compact  cpu10/   cpu14/   cpu18/   cpu20/   cpu24/   cpu28/   cpu32/   cpu36/   cpu4/    cpu8/    cpumap   
cpu0/    cpu12/   cpu16/   cpu2/    cpu22/   cpu26/   cpu30/   cpu34/   cpu38/   cpu6/    cpulist  
[root@node01 cpu]# ls /sys/devices/system/node/node1/c
compact  cpu11/   cpu15/   cpu19/   cpu23/   cpu27/   cpu3/    cpu33/   cpu37/   cpu5/    cpu9/    cpumap   
cpu1/    cpu13/   cpu17/   cpu21/   cpu25/   cpu29/   cpu31/   cpu35/   cpu39/   cpu7/    cpulist  
[root@node01 cpu]# ls /sys/devices/system/cpu/cpu
cpu0/    cpu11/   cpu14/   cpu17/   cpu2/    cpu22/   cpu25/   cpu28/   cpu30/   cpu33/   cpu36/   cpu39/   cpu6/    cpu9/
cpu1/    cpu12/   cpu15/   cpu18/   cpu20/   cpu23/   cpu26/   cpu29/   cpu31/   cpu34/   cpu37/   cpu4/    cpu7/    cpuidle/
cpu10/   cpu13/   cpu16/   cpu19/   cpu21/   cpu24/   cpu27/   cpu3/    cpu32/   cpu35/   cpu38/   cpu5/    cpu8/  


[root@node01 system]# cat /sys/devices/system/cpu/cpu34/topology/core_id
10
[root@node01 system]# cat /sys/devices/system/node/node0/cpu34/topology/core_id 
10


# 物理核
[root@node01 system]# find . -type f -name core_id  -exec sh -c 'echo -n {} && echo -n "     " && cat {}' \;
./cpu/cpu0/topology/core_id     0
./cpu/cpu1/topology/core_id     0
./cpu/cpu2/topology/core_id     1
./cpu/cpu3/topology/core_id     1
./cpu/cpu4/topology/core_id     2
./cpu/cpu5/topology/core_id     2
./cpu/cpu6/topology/core_id     3
./cpu/cpu7/topology/core_id     3
./cpu/cpu8/topology/core_id     4
./cpu/cpu9/topology/core_id     4
./cpu/cpu10/topology/core_id     8
./cpu/cpu11/topology/core_id     8
./cpu/cpu12/topology/core_id     9
./cpu/cpu13/topology/core_id     9
./cpu/cpu14/topology/core_id     10
./cpu/cpu15/topology/core_id     10
./cpu/cpu16/topology/core_id     11
./cpu/cpu17/topology/core_id     11
./cpu/cpu18/topology/core_id     12
./cpu/cpu19/topology/core_id     12
./cpu/cpu20/topology/core_id     0
./cpu/cpu21/topology/core_id     0
./cpu/cpu22/topology/core_id     1
./cpu/cpu23/topology/core_id     1
./cpu/cpu24/topology/core_id     2
./cpu/cpu25/topology/core_id     2
./cpu/cpu26/topology/core_id     3
./cpu/cpu27/topology/core_id     3
./cpu/cpu28/topology/core_id     4
./cpu/cpu29/topology/core_id     4
./cpu/cpu30/topology/core_id     8
./cpu/cpu31/topology/core_id     8
./cpu/cpu32/topology/core_id     9
./cpu/cpu33/topology/core_id     9
./cpu/cpu34/topology/core_id     10
./cpu/cpu35/topology/core_id     10
./cpu/cpu36/topology/core_id     11
./cpu/cpu37/topology/core_id     11
./cpu/cpu38/topology/core_id     12
./cpu/cpu39/topology/core_id     12

# 物理CPU
[root@node01 system]# find . -type f -name physical_package_id -exec sh -c 'echo -n {} && echo -n "     " && cat {}' \;
./cpu/cpu0/topology/physical_package_id     0
./cpu/cpu1/topology/physical_package_id     1
./cpu/cpu2/topology/physical_package_id     0
./cpu/cpu3/topology/physical_package_id     1
./cpu/cpu4/topology/physical_package_id     0
./cpu/cpu5/topology/physical_package_id     1
./cpu/cpu6/topology/physical_package_id     0
./cpu/cpu7/topology/physical_package_id     1
./cpu/cpu8/topology/physical_package_id     0
./cpu/cpu9/topology/physical_package_id     1
./cpu/cpu10/topology/physical_package_id     0
./cpu/cpu11/topology/physical_package_id     1
./cpu/cpu12/topology/physical_package_id     0
./cpu/cpu13/topology/physical_package_id     1
./cpu/cpu14/topology/physical_package_id     0
./cpu/cpu15/topology/physical_package_id     1
./cpu/cpu16/topology/physical_package_id     0
./cpu/cpu17/topology/physical_package_id     1
./cpu/cpu18/topology/physical_package_id     0
./cpu/cpu19/topology/physical_package_id     1
./cpu/cpu20/topology/physical_package_id     0
./cpu/cpu21/topology/physical_package_id     1
./cpu/cpu22/topology/physical_package_id     0
./cpu/cpu23/topology/physical_package_id     1
./cpu/cpu24/topology/physical_package_id     0
./cpu/cpu25/topology/physical_package_id     1
./cpu/cpu26/topology/physical_package_id     0
./cpu/cpu27/topology/physical_package_id     1
./cpu/cpu28/topology/physical_package_id     0
./cpu/cpu29/topology/physical_package_id     1
./cpu/cpu30/topology/physical_package_id     0
./cpu/cpu31/topology/physical_package_id     1
./cpu/cpu32/topology/physical_package_id     0
./cpu/cpu33/topology/physical_package_id     1
./cpu/cpu34/topology/physical_package_id     0
./cpu/cpu35/topology/physical_package_id     1
./cpu/cpu36/topology/physical_package_id     0
./cpu/cpu37/topology/physical_package_id     1
./cpu/cpu38/topology/physical_package_id     0
./cpu/cpu39/topology/physical_package_id     1





# 物理核

物理cpu 0: 物理核0 物理核1 物理核2 物理核3 物理核4 物理核8 物理核9 物理核10 物理核11 物理核12 

物理cpu 1: 物理核0 物理核1 物理核2 物理核3 物理核4 物理核8 物理核9 物理核10 物理核11 物理核12  


# 逻辑核

物理CPU0:    逻辑核[0, 20]   逻辑核[2, 22]   逻辑核[4, 24]   逻辑核[6, 26]   逻辑核[8, 28]   逻辑核[10, 30]   逻辑核[12, 32]   逻辑核[14, 34]   逻辑核[16, 36]   逻辑核[18, 38]   
物理CPU1:    逻辑核[1, 21]   逻辑核[3, 23]   逻辑核[5, 25]   逻辑核[7, 27]   逻辑核[9, 29]   逻辑核[11, 31]   逻辑核[13, 33]   逻辑核[15, 35]   逻辑核[17, 37]   逻辑核[19, 39]   



[root@node01 cache]# find /sys/devices/system/cpu/cpu0/cache -name type -exec sh -c 'echo -n {} && echo -n "     " && cat {}' \;
/sys/devices/system/cpu/cpu0/cache/index0/type     Data
/sys/devices/system/cpu/cpu0/cache/index1/type     Instruction
/sys/devices/system/cpu/cpu0/cache/index2/type     Unified
/sys/devices/system/cpu/cpu0/cache/index3/type     Unified
[root@node01 cache]# find /sys/devices/system/cpu/cpu0/cache -name size -exec sh -c 'echo -n {} && echo -n "     " && cat {}' \;
/sys/devices/system/cpu/cpu0/cache/index0/size     32K
/sys/devices/system/cpu/cpu0/cache/index1/size     32K
/sys/devices/system/cpu/cpu0/cache/index2/size     256K
/sys/devices/system/cpu/cpu0/cache/index3/size     25600K
[root@node01 cache]# lscpu|grep cache
L1d cache:             32K
L1i cache:             32K
L2 cache:              256K
L3 cache:              25600K






```



```
import copy
import re
import subprocess

core_ids = {}
res = subprocess.getoutput(
    """find /sys/devices/system -type f -name core_id  -exec sh -c 'echo -n {} && echo -n "     " && cat {}' \;""")
for item in res.strip().split('\n'):
    _ids = re.findall('(\d+)', item)
    core_ids[int(_ids[0])] = int(_ids[1])

physical_package_ids = {}
res = subprocess.getoutput(
    """find /sys/devices/system -type f -name physical_package_id  -exec sh -c 'echo -n {} && echo -n "     " && cat {}' \;""")
for item in res.strip().split('\n'):
    _ids = re.findall('(\d+)', item)
    physical_package_ids[int(_ids[0])] = int(_ids[1])

res = [[[]] * (max(core_ids.values()) + 1)] * (max(physical_package_ids.values()) + 1)

for k, v in core_ids.items():
    res[physical_package_ids[k]] = copy.deepcopy(res[physical_package_ids[k]])
    res[physical_package_ids[k]][core_ids[k]] = copy.deepcopy(res[physical_package_ids[k]][core_ids[k]])
    res[physical_package_ids[k]][core_ids[k]].append(k)
    res[physical_package_ids[k]][core_ids[k]].sort()

for _w, items in enumerate(res):
    print("物理CPU%s: " % _w, end='   ')

    for i, item in enumerate(items):
        if len(item) > 0:
            print("逻辑核:", item, end='   ')
    print()
```


``` 
[root@node01 ]# cat /sys/devices/system/node/node1/meminfo 
Node 1 MemTotal:       132116772 kB
Node 1 MemFree:        43569776 kB
Node 1 MemUsed:        88546996 kB
Node 1 Active:         50777192 kB
Node 1 Inactive:       33044708 kB
Node 1 Active(anon):   10684252 kB
Node 1 Inactive(anon):  1164208 kB
Node 1 Active(file):   40092940 kB
Node 1 Inactive(file): 31880500 kB
Node 1 Unevictable:           0 kB
Node 1 Mlocked:               0 kB
Node 1 Dirty:               136 kB
Node 1 Writeback:             0 kB
Node 1 FilePages:      75750296 kB
Node 1 Mapped:           320872 kB
Node 1 AnonPages:       8071856 kB
Node 1 Shmem:           3776848 kB
Node 1 KernelStack:       27216 kB
Node 1 PageTables:        30940 kB
Node 1 NFS_Unstable:          0 kB
Node 1 Bounce:                0 kB
Node 1 WritebackTmp:          0 kB
Node 1 Slab:            3655204 kB
Node 1 SReclaimable:    3387648 kB
Node 1 SUnreclaim:       267556 kB
Node 1 AnonHugePages:   1241088 kB
Node 1 HugePages_Total:     0
Node 1 HugePages_Free:      0
Node 1 HugePages_Surp:      0
```










## 大体流程
- 针对是pod、还是container 进行资源的admit
    - pod 是获取所有资源,进行一次
    - container 是每一个都进行一次
  - 针对每种资源,获取到符合对应的需求的numa组合   ①
  - 从每种资源 对应的numa 组合中, 各选一个（m*n*i*j种组合）, 执行相应的比较程序
    - 如果选取的这个种资源的组合,numa组合一致,视为 Preferred  .并将这些组合numa mask 按位与 , 过去共有的核
    - 再从众多的结果中选取 Preferred、numa数量最低、numa节点平均距离对低 的作为 bestHint
- 将获取的最佳numa配置保存在mem、dist
- 实际分配时, 从其中读取已分配的 numa 配置


- numa 组合默认为全部numa node
- single_numa_node 是在①生效,选取只有一个numa节点的
  - 准入取决 于是否有numa 组合 Preferred 为true
- restricted
  - 准入取决 于是否有numa 组合 Preferred 为true
- best-effort
  - 总是允许准入
- none 
  - 总是允许准入
  
- -prefer-closest-numa-nodes 只能在 best-effort、restricted 时设置. 在numa 数量一致时,比较各自numa节点间的距离平均值 `numactl --hardware`

```
[{cpu 0} {mem 0} {gpu 0}]
[{cpu 0} {mem 0} {gpu 1}]
[{cpu 0} {mem 0} {gpu 2}]
[{cpu 0} {mem 0} {gpu 3}]
[{cpu 0} {mem 1} {gpu 0}]
[{cpu 0} {mem 1} {gpu 1}]
[{cpu 0} {mem 1} {gpu 2}]
[{cpu 0} {mem 1} {gpu 3}]
[{cpu 0} {mem 2} {gpu 0}]
[{cpu 0} {mem 2} {gpu 1}]
[{cpu 0} {mem 2} {gpu 2}]
[{cpu 0} {mem 2} {gpu 3}]
[{cpu 0} {mem 3} {gpu 0}]
[{cpu 0} {mem 3} {gpu 1}]
[{cpu 0} {mem 3} {gpu 2}]
[{cpu 0} {mem 3} {gpu 3}]
[{cpu 1} {mem 0} {gpu 0}]
[{cpu 1} {mem 0} {gpu 1}]
[{cpu 1} {mem 0} {gpu 2}]
[{cpu 1} {mem 0} {gpu 3}]
[{cpu 1} {mem 1} {gpu 0}]
[{cpu 1} {mem 1} {gpu 1}]
[{cpu 1} {mem 1} {gpu 2}]
[{cpu 1} {mem 1} {gpu 3}]
[{cpu 1} {mem 2} {gpu 0}]
[{cpu 1} {mem 2} {gpu 1}]
[{cpu 1} {mem 2} {gpu 2}]
[{cpu 1} {mem 2} {gpu 3}]
[{cpu 1} {mem 3} {gpu 0}]
[{cpu 1} {mem 3} {gpu 1}]
[{cpu 1} {mem 3} {gpu 2}]
[{cpu 1} {mem 3} {gpu 3}]
[{cpu 2} {mem 0} {gpu 0}]
[{cpu 2} {mem 0} {gpu 1}]
[{cpu 2} {mem 0} {gpu 2}]
[{cpu 2} {mem 0} {gpu 3}]
[{cpu 2} {mem 1} {gpu 0}]
[{cpu 2} {mem 1} {gpu 1}]
[{cpu 2} {mem 1} {gpu 2}]
[{cpu 2} {mem 1} {gpu 3}]
[{cpu 2} {mem 2} {gpu 0}]
[{cpu 2} {mem 2} {gpu 1}]
[{cpu 2} {mem 2} {gpu 2}]
[{cpu 2} {mem 2} {gpu 3}]
[{cpu 2} {mem 3} {gpu 0}]
[{cpu 2} {mem 3} {gpu 1}]
[{cpu 2} {mem 3} {gpu 2}]
[{cpu 2} {mem 3} {gpu 3}]
[{cpu 3} {mem 0} {gpu 0}]                                                                                         
[{cpu 3} {mem 0} {gpu 1}]                                                                                         
[{cpu 3} {mem 0} {gpu 2}]                                                                                         
[{cpu 3} {mem 0} {gpu 3}]                                                                                         
[{cpu 3} {mem 1} {gpu 0}]                                                                                         
[{cpu 3} {mem 1} {gpu 1}]                                                                                         
[{cpu 3} {mem 1} {gpu 2}]                                                                                         
[{cpu 3} {mem 1} {gpu 3}]                                                                                         
[{cpu 3} {mem 2} {gpu 0}]                                                                                         
[{cpu 3} {mem 2} {gpu 1}]                                                                                         
[{cpu 3} {mem 2} {gpu 2}]                                                                                         
[{cpu 3} {mem 2} {gpu 3}]                                                                                         
[{cpu 3} {mem 3} {gpu 0}]                                                                                         
[{cpu 3} {mem 3} {gpu 1}]                                                                                         
[{cpu 3} {mem 3} {gpu 2}]                                                                                         
[{cpu 3} {mem 3} {gpu 3}]                                                                                         
```