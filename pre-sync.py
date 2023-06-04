from sync import *

path = 'export PATH="' + os.getcwd() + '/third_party/etcd:${PATH}"'
print('-->', path)
system(
    path +
    ' && ./hack/install-etcd.sh && ./hack/update-generated-swagger-docs.sh && ./hack/update-codegen.sh && ./hack/update-openapi-spec.sh'
)

system("cd cmd && go build ./... && go clean")
system("sudo rm -rf _output vendor")
