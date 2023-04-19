import os
import shutil

os.system("sudo rm -rf vendor _output")
os.system("go mod vendor")


def catch_dir(path, level: int):
    res = []
    for cur, dirs, _ in os.walk(path):
        for _dir in dirs:
            p = os.path.join(cur, _dir)
            if p.count(os.sep) == 3 + level:
                res.append(p[len('./staging/src/'):])
    return res


item = 'k8s.io'
for _item in catch_dir(f'./staging/src/{item}', 1):
    shutil.rmtree(f'./vendor/{_item}', ignore_errors=True)
    shutil.copytree(f'./staging/src/{_item}', f'./vendor/{_item}')

item = 'github.com'
for _item in catch_dir(f'./staging/src/{item}', 2):
    shutil.rmtree(f'./vendor/{_item}', ignore_errors=True)
    shutil.copytree(f'./staging/src/{_item}', f'./vendor/{_item}')

os.system('./hack/update-generated-swagger-docs.sh && ./hack/update-codegen.sh && ./hack/update-openapi-spec.sh')
