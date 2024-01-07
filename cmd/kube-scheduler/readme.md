PriorityQueue:
```
    activeQ                           *heap.Heap        
    podBackoffQ                       *heap.Heap        
    unschedulablePods                 *UnschedulablePods
    
    unschedulablePods -> activeQ
                      -> podBackoffQ
    
    
```



Scheduler
```
    SchedulingQueue: PriorityQueue




```
type frameworkImpl struct {
    waitingPods         调度PermitPlugin 返回 Wait
}

Reserve     ->  Unreserve

pod -> assumeCache[pod] -> Restore[store[pod]]


state := framework.NewCycleState() 在整个pod 的一次调度周期内存在

type Extender struct {}

未调度的pod
    - 执行每个 runPreEnqueuePlugins，都成功 加入 ActiveQ 发信号
    - 有一个失败，加入 unschedulablePods

 


从 ActiveQ 获取 pod

schedulingCycle
    - SchedulePod     
        - findNodesThatFitPod
            - RunPreFilterPlugins
            # - evaluateNominatedNode         只有一个候选节点 可选
            - findNodesThatPassFilters
                - SelectVictimsOnNode
                  - RunPreFilterExtensionRemovePod
                    - runPreFilterExtensionRemovePod
                - RunFilterPluginsWithNominatedPods
                    - addNominatedPods
                        - RunPreFilterExtensionAddPod
                            - runPreFilterExtensionAddPod  
                    - RunFilterPlugins          
            - findNodesThatPassExtenders        // post 请求
        - prioritizeNodes
            - RunPreScorePlugins
            - RunScorePlugins
            - RunScorePlugins
        - selectHost                        选择分数最高的
    - PostFilterPlugins                     (调度失败且返回错误是FitError, 会被调用) 只有一个成功或可调度的处理方,默认 DefaultBinder
        - Preempt
    - ReservePluginsReserve                 进行资源的预留和检查，以确保在调度 Pod 时有足够的资源可用   【内存里】
        - RunReservePluginsUnreserve        从watch 缓存中还原数据
    - PermitPlugins                         可以有很多插件, 返回 Wait、Success、Error ;Wait 加入waitingPods
        - RunReservePluginsUnreserve




( PreFilter ) 

bindingCycle
    - WaitOnPermit 
    - PreBind(volume更新绑定信息...) 
    - Bind
        - extendersBinding                  只有一个处理方
        - BindPlugins                       只有一个非SKIP的处理方,默认 DefaultBinder
    - PostBind 
  



# todo 
- PodTopologySpread