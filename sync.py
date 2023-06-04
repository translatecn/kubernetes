import os
import shutil
import subprocess


def system(s):
    print('--->', s)
    os.system(s)


a = subprocess.getoutput(f"find {os.path.dirname(os.path.abspath(__file__))}|grep -v vendor |grep 'go.mod'")
system('go env -w GOPROXY="https://goproxy.cn/,direct"')
system("sudo rm -rf vendor _output")
shutil.rmtree('./_output', ignore_errors=True)

for current_dir, dirs, files in os.walk(os.path.dirname(os.path.abspath(__file__))):
    for file in files:
        path = os.path.join(current_dir, file)
        if path.endswith(".go") or path.endswith('.md'):
            with open(path, 'r', encoding='utf8') as f:
                data = f.read()
            for item in [
                ['，', ','],
                ['。', '.'],
            ]:
                data = data.replace(item[0], item[1])

            with open(path, 'w', encoding='utf8') as f:
                f.write(data)
print('---> go mod vendor')
system("go mod vendor")
print('---> pkill -9 etcd')
system("pkill -9 etcd")
system("pkill -9 apiserver")
system("pkill -9 kube-apiserver")
system("ps -ef |grep apiserver")

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

    system(f'cd "{git_path}" && go mod tidy')
    print(f"last :{len(git_set) - i}")


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

for item in a.split('\n'):
    item = os.path.dirname(item.strip())
    print(f'cd {item} && go mod tidy')
    system(f'cd {item} && go mod tidy')
