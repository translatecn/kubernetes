package userns

// RunningInUserNS 检测当前是否在用户命名空间中运行。
// 最初从 github.com/lxc/lxd/shared/util.go 复制而来。
var RunningInUserNS = runningInUserNS
