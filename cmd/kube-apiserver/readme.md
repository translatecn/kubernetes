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