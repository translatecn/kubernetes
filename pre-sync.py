import os
import shutil

os.system("sudo rm -rf vendor _output")
os.system("go mod vendor")
os.system("pkill -9 etcd")
os.system("pkill -9 apiserver")
os.system("pkill -9 kube-apiserver")
os.system("ps -ef |grep apiserver")


git_set = []


# root_path
def get_file_path(root_path, dir_list=[], _set="uploaded_set"):
    # 获取该目录下所有的文件名称和目录名称
    dir_or_files = os.listdir(root_path)
    for dir_file in dir_or_files:
        # 获取目录或者文件的路径
        dir_file_path = os.path.join(root_path, dir_file)
        # 判断该路径为文件还是路径
        if os.path.isdir(dir_file_path):
            if dir_file_path.endswith('vendor'):
                continue
            dir_list.append(dir_file_path)
            # 递归获取所有文件和目录的路径
            get_file_path(dir_file_path, dir_list)
        if dir_file_path.endswith('.mod'):
            git_set.append(dir_file_path)


get_file_path(os.path.dirname(__file__))
print('\n'.join(git_set))
for i, git in enumerate(git_set):
    git_path = os.path.dirname(git)
    print(git_path)

    os.system(f'cd "{git_path}" && go mod tidy')
    print(f"last :{len(git_set)-i}")




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


path = 'export PATH="'+ os.getcwd() +'/third_party/etcd:${PATH}"'
os.system(path + ' && ./hack/update-generated-swagger-docs.sh && ./hack/update-codegen.sh && ./hack/update-openapi-spec.sh')
os.system("sudo rm -rf vendor _output")