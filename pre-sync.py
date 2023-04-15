import os
import subprocess

os.system("sudo rm -rf vendor _output")
os.system("go mod vendor")
os.system('cp -fr  ./staging/src/ ./vendor/')
res = subprocess.getoutput("find ./vendor|grep over-")
for line in res.strip().split('\n'):
    line = line.strip().replace('over-', '')
    try:
        os.remove(os.path.abspath(os.path.join('/Users/acejilam/Desktop/kubernetes', line)))
    except Exception:
        pass
