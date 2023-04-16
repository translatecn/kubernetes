import os
import shutil

os.system("sudo rm -rf vendor _output")
os.system("go mod vendor")

_, dirs, _ = list(os.walk('./staging/src/k8s.io'))[0]

for _dir in dirs:
    shutil.rmtree(os.path.join('./vendor/k8s.io', _dir), ignore_errors=True)
    shutil.copytree(os.path.join('./staging/src/k8s.io', _dir), os.path.join('./vendor/k8s.io', _dir))

os.system('./hack/update-generated-swagger-docs.sh && ./hack/update-codegen.sh && ./hack/update-openapi-spec.sh')
