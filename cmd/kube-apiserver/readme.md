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
- https://devpress.csdn.net/k8s/62ee61a17e6682346618233f.html
- https://www.ibm.com/docs/zh/was-liberty/base?topic=connect-configuring-json-web-token-authentication-openid
- https://www.jianshu.com/p/75b865e55568
- https://kubernetes.io/zh-cn/docs/reference/access-authn-authz/authentication/
- https://www.cnblogs.com/huanglingfa/p/13773344.html

