- https://www.jianshu.com/p/88ec8cba7507
- https://www.jianshu.com/p/5c6e78b6b320













git clone git@github.com:kubernetes-retired/drivers.git /tmp/drivers
mv /tmp/drivers/pkg/csi-common .
go mod tidy 




### test
go get github.com/rexray/gocsi/csc
git clone git@github.com:kubernetes-csi/csi-test.git /tmp/csi-test
cd /tmp/csi-test/cmd/csi-sanity
make
mv csi-sanity $GOPATH/bin
cd -

- 直接运行main函数
  - go run main.go --endpoint tcp://127.0.0.1:10000  --nodeid deploy-node -v 5
- 测试创建卷
  - csc controller create-volume --endpoint tcp://127.0.0.1:10000 test1
- 测试挂载卷
  - csc node publish --endpoint tcp://127.0.0.1:10000 --target-path "/tmp/test1" --cap MULTI_NODE_MULTI_WRITER,mount,xfs,uid=0,gid=0 $volumeID --attrib $VolumeContext
- 运行单元测试
  - csi-sanity --csi.endpoint=127.0.0.1:10000 -csi.testvolumeparameters config.yaml -ginkgo.v 5
