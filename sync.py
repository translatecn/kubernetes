import os
import subprocess

a = subprocess.getoutput(f"find {os.path.dirname(os.path.abspath(__file__))}|grep 'go.mod'")

for item in a.split('\n'):
    item = os.path.dirname(item.strip())
    os.system(f'cd {item} && go mod tidy')

#
# for item in a.split('\n'):
#     item = item.strip()
#     xs = []
#     with open(item, 'r', encoding='utf8') as f:
#         for line in f.readlines():
#             line = line.strip()
#             if line.startswith('k8s.io') and 'v0.0.0' not in line and '=>' not in line:
#                 x = line.split(' ')[0]
#                 xs.append(f'{x} => ../{x[7:]}')
#
#     with open(item, 'a+', encoding='utf8') as f:
#         f.write('\n')
#         f.write('replace (\n' + "\n".join(xs) + '\n)')
