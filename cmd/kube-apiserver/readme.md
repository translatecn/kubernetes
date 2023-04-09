Complete
Run
- CreateServerChain
  - CreateKubeAPIServerConfig
    - buildGenericConfig
    - AddPostStartHook
  - createAPIExtensionsConfig
  - createAPIExtensionsServer
  - CreateKubeAPIServer
  - createAggregatorServer
- PrepareRun
  - s.installHealthz() 
  - s.installLivez()
  - s.installReadyz()
- Run








- AuthenticateRequest 认证函数
- DefaultBuildHandlerChain 中间件函数
- https://blog.csdn.net/qq_24433609/article/details/127192871
- 