import copy
import re
import subprocess

core_ids = {}
res = subprocess.getoutput(
    r"""find /sys/devices/system -type f -name core_id  -exec sh -c 'echo -n {} && echo -n "     " && cat {}' \;""")
for item in res.strip().split('\n'):
    _ids = re.findall(r'(\d+)', item)
    core_ids[int(_ids[0])] = int(_ids[1])

physical_package_ids = {}
res = subprocess.getoutput(
    r"""find /sys/devices/system -type f -name physical_package_id  -exec sh -c 'echo -n {} && echo -n "     " && cat 
    {}' \;""")
for item in res.strip().split('\n'):
    _ids = re.findall(r'(\d+)', item)
    physical_package_ids[int(_ids[0])] = int(_ids[1])

res = [[[]] * (max(core_ids.values()) + 1)] * (max(physical_package_ids.values()) + 1)

for k, v in core_ids.items():
    res[physical_package_ids[k]] = copy.deepcopy(res[physical_package_ids[k]])
    res[physical_package_ids[k]][core_ids[k]] = copy.deepcopy(res[physical_package_ids[k]][core_ids[k]])
    res[physical_package_ids[k]][core_ids[k]].append(k)
    res[physical_package_ids[k]][core_ids[k]].sort()

for _w, items in enumerate(res):
    print("物理CPU%s: " % _w, end='   ')

    for i, item in enumerate(items):
        if len(item) > 0:
            print("逻辑核:", item, end='   ')
    print()
