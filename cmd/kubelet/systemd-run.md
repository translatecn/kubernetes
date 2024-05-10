以下是一个使用 systemd-run 进行挂载的完整示例：

1. 创建一个系统服务文件 `/etc/systemd/system/my-mount.service`,内容如下：

```
[Unit]
Description=My Mount Service
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/systemd-run --scope /bin/mount /dev/sdb1 /mnt/my-mount

[Install]
WantedBy=multi-user.target
```

在上面的示例中,我们创建了一个名为 my-mount 的服务,它会在启动时挂载 /dev/sdb1 到 /mnt/my-mount.ExecStart 命令使用 systemd-run 运行 mount 命令.Type 设置为 oneshot,表示服务只会运行一次.RemainAfterExit 设置为 yes,表示服务会在退出后继续保持运行状态.After 设置为 network-online.target,表示服务会在网络连接成功后启动.

2. 启动服务：

```
sudo systemctl daemon-reload
sudo systemctl start my-mount.service
```

在上面的示例中,我们重新加载 systemd,并启动 my-mount 服务.

3. 查看服务状态：

```
sudo systemctl status my-mount.service
```

在上面的示例中,我们查看 my-mount 服务的状态.

4. 停止服务：

```
sudo systemctl stop my-mount.service
```

在上面的示例中,我们停止 my-mount 服务.

以上就是使用 systemd-run 进行挂载的完整示例.注意,该示例仅适用于系统服务,如果要在容器中使用 systemd-run 进行挂载,则需要先确保容器中的 systemd 正确运行.