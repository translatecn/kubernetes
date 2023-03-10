## Kubernetes源码阅读&&注解

### 项目思路：
目前在学习看k8s源码，并在上面加上一些注解与简易文档。欢迎大家提交pr或文档，也欢迎大家的指正点评。

### cmd
```
.
├── clicheck
├── cloud-controller-manager
├── dependencycheck
├── dependencyverifier
├── fieldnamedocscheck
├── gendocs
├── genkubedocs
├── genman                              打印api-server...的命令参数、flag
├── genswaggertypedocs
├── genutils
├── genyaml
├── importverifier                      校验包依赖
├── kube-apiserver
├── kube-controller-manager
├── kube-proxy
├── kube-scheduler
├── kubeadm
├── kubectl
├── kubectl-convert
├── kubelet
├── kubemark
├── preferredimports                    替换包别名，格式化代码
├── prune-junit-xml                     格式化xml 数据
└── yamlfmt                             格式化yaml数据

```
### RoadMap:
近期预计更新的组件源码注释
```
1. Scheduler
2. Apiserver
3. Controller-manager
4. Informer模块
```

### 源码入口
```
1. Scheduler: cmd/kube-scheduler/scheduler.go
2. Apiserver: cmd/kube-apiserver/apiserver.go
3. Controller-manager: cmd/kube-controller-manager/controller-manager.go
```

### 参考资料
