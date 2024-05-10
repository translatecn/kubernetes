在 cgroup2 中,可以通过 `memory.max` 文件来设置内存最大可用量,通过 `memory.current` 文件来查看当前内存使用量.

以下是通过命令行查看内存可用量的示例：

1. 创建一个 cgroup2：

```
$ sudo mkdir /sys/fs/cgroup/unified/mygroup
```

2. 将当前进程加入到该 cgroup2 中：

```
$ echo $$ | sudo tee /sys/fs/cgroup/unified/mygroup/cgroup.procs
```

3. 设置内存最大可用量为 1GB：

```
$ echo 1G | sudo tee /sys/fs/cgroup/unified/mygroup/memory.max
```

4. 查看当前内存使用量：

```
$ cat /sys/fs/cgroup/unified/mygroup/memory.current
```

该命令会输出当前内存使用量的字节数.如果需要将其转换为人类可读的格式,可以使用 `numfmt` 命令,如下所示：

```
$ cat /sys/fs/cgroup/unified/mygroup/memory.current | numfmt --to=iec-i --suffix=B
```

该命令会输出当前内存使用量的人类可读格式,例如“512MiB”.