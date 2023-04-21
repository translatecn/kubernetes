## kubelet启动了哪些模块
- prometheus指标相关
- cadvisor采集容器指标
- 创建文件目录 initializeModules.setupDataDirs
  1. the root directory
  2. the pods directory
  3. the plugins directory
  4. the pod-resources directory
- 创建/var/log/containers 容器日志目录
- image镜像相关
  - kl.imageManager.Start
- 证书管理器
  - kl.serverCertificateManager.Start
- oom watcher
  - kl.oomWatcher.Start
- 资源分析器
  - kl.resourceAnalyzer.Start()
- 与apiserver同步节点状态
  - kl.syncNodeStatus
- iptables管理器
  - kl.initNetworkUtil
- containerManager 容器管理器
  - cpu管理器 cm.cpuManager.Start
  - 内存管理器 cm.memoryManager.Start
  - 磁盘管理器 cm.deviceManager.Start
- 驱逐管理器 kl.evictionManager.Start
- 插件管理器 kl.pluginManager.Run
- 和apiserver的pod信息同步器
- 存活探针管理器 livenessManager
- 就绪探针管理器 readinessManager
