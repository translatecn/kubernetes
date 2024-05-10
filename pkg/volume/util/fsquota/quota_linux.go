//go:build linux
// +build linux

/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package fsquota

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"k8s.io/klog/v2"
	"k8s.io/mount-utils"

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/kubernetes/pkg/volume/util/fsquota/common"
)

// Pod -> ID
var podQuotaMap = make(map[types.UID]common.QuotaID)

// Dir -> ID (for convenience)
var dirQuotaMap = make(map[string]common.QuotaID)

// ID -> pod
var quotaPodMap = make(map[common.QuotaID]types.UID)

// Directory -> pod
var dirPodMap = make(map[string]types.UID)

// Backing device -> applier
// This is *not* cleaned up; its size will be bounded.
var devApplierMap = make(map[string]common.LinuxVolumeQuotaApplier)

// Directory -> applier
var dirApplierMap = make(map[string]common.LinuxVolumeQuotaApplier)
var dirApplierLock sync.RWMutex

// Pod -> refcount
var podDirCountMap = make(map[types.UID]int)

// ID -> size
var quotaSizeMap = make(map[common.QuotaID]int64)
var quotaLock sync.RWMutex

var supportsQuotasMap = make(map[string]bool)
var supportsQuotasLock sync.RWMutex

// Directory -> backingDev
var backingDevMap = make(map[string]string)
var backingDevLock sync.RWMutex

var mountpointMap = make(map[string]string)
var mountpointLock sync.RWMutex

var providers = []common.LinuxVolumeQuotaProvider{
	&common.VolumeProvider{},
}

func clearBackingDev(path string) {
	backingDevLock.Lock()
	defer backingDevLock.Unlock()
	delete(backingDevMap, path)
}

func clearMountpoint(path string) {
	mountpointLock.Lock()
	defer mountpointLock.Unlock()
	delete(mountpointMap, path)
}

func clearFSInfo(path string) {
	clearMountpoint(path)
	clearBackingDev(path)
}

func getApplier(path string) common.LinuxVolumeQuotaApplier {
	dirApplierLock.Lock()
	defer dirApplierLock.Unlock()
	return dirApplierMap[path]
}

func setApplier(path string, applier common.LinuxVolumeQuotaApplier) {
	dirApplierLock.Lock()
	defer dirApplierLock.Unlock()
	dirApplierMap[path] = applier
}

func setQuotaOnDir(path string, id common.QuotaID, bytes int64) error {
	return getApplier(path).SetQuotaOnDir(path, id, bytes)
}

func getQuotaOnDir(m mount.Interface, path string) (common.QuotaID, error) {
	_, _, err := getFSInfo(m, path)
	if err != nil {
		return common.BadQuotaID, err
	}
	return getApplier(path).GetQuotaOnDir(path)
}

// AssignQuota -- assign a quota to the specified directory.
// AssignQuota chooses the quota ID based on the pod UID and path.
// If the pod UID is identical to another one known, it may (but presently
// doesn't) choose the same quota ID as other volumes in the pod.
func AssignQuota(m mount.Interface, path string, poduid types.UID, bytes *resource.Quantity) error { //nolint:staticcheck // SA4009 poduid is overwritten by design, see comment below
	if bytes == nil {
		return fmt.Errorf("attempting to assign null quota to %s", path)
	}
	ibytes := bytes.Value()
	if ok, err := SupportsQuotas(m, path); !ok {
		return fmt.Errorf("quotas not supported on %s: %v", path, err)
	}
	quotaLock.Lock()
	defer quotaLock.Unlock()
	// Current policy is to set individual quotas on each volumes.
	// If we decide later that we want to assign one quota for all
	// volumes in a pod, we can simply remove this line of code.
	// If and when we decide permanently that we're going to adopt
	// one quota per volume, we can rip all of the pod code out.
	poduid = types.UID(uuid.NewUUID()) //nolint:staticcheck // SA4009 poduid is overwritten by design, see comment above
	if pod, ok := dirPodMap[path]; ok && pod != poduid {
		return fmt.Errorf("requesting quota on existing directory %s but different pod %s %s", path, pod, poduid)
	}
	oid, ok := podQuotaMap[poduid]
	if ok {
		if quotaSizeMap[oid] != ibytes {
			return fmt.Errorf("requesting quota of different size: old %v new %v", quotaSizeMap[oid], bytes)
		}
	} else {
		oid = common.BadQuotaID
	}
	id, err := createProjectID(path, oid)
	if err == nil {
		if oid != common.BadQuotaID && oid != id {
			return fmt.Errorf("attempt to reassign quota %v to %v", oid, id)
		}
		// When enforcing quotas are enabled, we'll condition this
		// on their being disabled also.
		if ibytes > 0 {
			ibytes = -1
		}
		if err = setQuotaOnDir(path, id, ibytes); err == nil {
			quotaPodMap[id] = poduid
			quotaSizeMap[id] = ibytes
			podQuotaMap[poduid] = id
			dirQuotaMap[path] = id
			dirPodMap[path] = poduid
			podDirCountMap[poduid]++
			klog.V(4).Infof("Assigning quota ID %d (%d) to %s", id, ibytes, path)
			return nil
		}
		removeProjectID(path, id)
	}
	return fmt.Errorf("assign quota FAILED %v", err)
}

// GetConsumption -- retrieve the consumption (in bytes) of the directory
func GetConsumption(path string) (*resource.Quantity, error) {
	// Note that we actually need to hold the lock at least through
	// running the quota command, so it can't get recycled behind our back
	quotaLock.Lock()
	defer quotaLock.Unlock()
	applier := getApplier(path)
	// No applier means directory is not under quota management
	if applier == nil {
		return nil, nil
	}
	ibytes, err := applier.GetConsumption(path, dirQuotaMap[path])
	if err != nil {
		return nil, err
	}
	return resource.NewQuantity(ibytes, resource.DecimalSI), nil
}

// GetInodes -- retrieve the number of inodes in use under the directory
func GetInodes(path string) (*resource.Quantity, error) {
	// Note that we actually need to hold the lock at least through
	// running the quota command, so it can't get recycled behind our back
	quotaLock.Lock()
	defer quotaLock.Unlock()
	applier := getApplier(path)
	// No applier means directory is not under quota management
	if applier == nil {
		return nil, nil
	}
	inodes, err := applier.GetInodes(path, dirQuotaMap[path])
	if err != nil {
		return nil, err
	}
	return resource.NewQuantity(inodes, resource.DecimalSI), nil
}

// ------------------------------------------------------------------------------------------------------------------

// SupportsQuotas 判断一个路径是否支持配额.如果支持配额,则缓存应用程序以供使用,如果不支持,则不缓存结果,因为没有东西可以清除它.
// 但是,该设备->应用程序映射会被缓存,因为设备数量是有限的.
// 此外,注释还提到了一个名为NewWrapperUnmounter的函数,该函数用于查找适当的插件来处理提供的规范.有关更多上下文,请参见NewWrapperMounter的注释.
func SupportsQuotas(m mount.Interface, path string) (bool, error) {
	if !enabledQuotasForMonitoring() {
		klog.V(3).Info("SupportsQuotas called, but quotas disabled")
		return false, nil
	}
	supportsQuotasLock.Lock()
	defer supportsQuotasLock.Unlock()
	if supportsQuotas, ok := supportsQuotasMap[path]; ok {
		return supportsQuotas, nil
	}
	mount, dev, err := getFSInfo(m, path)
	if err != nil {
		return false, err
	}
	// Do we know about this device?
	applier, ok := devApplierMap[mount]
	if !ok {
		for _, provider := range providers {
			if applier = provider.GetQuotaApplier(mount, dev); applier != nil {
				devApplierMap[mount] = applier
				break
			}
		}
	}
	if applier != nil {
		supportsQuotasMap[path] = true
		setApplier(path, applier)
		return true, nil
	}
	delete(backingDevMap, path)
	delete(mountpointMap, path)
	return false, nil
}

func clearQuotaOnDir(m mount.Interface, path string) error {
	// Since we may be called without path being in the map,
	// we explicitly have to check in this case.
	klog.V(4).Infof("clearQuotaOnDir %s", path)
	supportsQuotas, err := SupportsQuotas(m, path)
	if err != nil {
		// Log-and-continue instead of returning an error for now
		// due to unspecified backwards compatibility concerns (a subject to revise)
		klog.V(3).Infof("Attempt to check for quota support failed: %v", err)
	}
	if !supportsQuotas {
		return nil
	}
	projid, err := getQuotaOnDir(m, path)
	if err == nil && projid != common.BadQuotaID {
		// This means that we have a quota on the directory but
		// we can't clear it.  That's not good.
		err = setQuotaOnDir(path, projid, 0)
		if err != nil {
			klog.V(3).Infof("Attempt to clear quota failed: %v", err)
		}
		// Even if clearing the quota failed, we still need to
		// try to remove the project ID, or that may be left dangling.
		err1 := removeProjectID(path, projid)
		if err1 != nil {
			klog.V(3).Infof("Attempt to remove quota ID from system files failed: %v", err1)
		}
		clearFSInfo(path)
		if err != nil {
			return err
		}
		return err1
	}
	// If we couldn't get a quota, that's fine -- there may
	// never have been one, and we have no way to know otherwise
	klog.V(3).Infof("clearQuotaOnDir fails %v", err)
	return nil
}

func clearApplier(path string) {
	dirApplierLock.Lock()
	defer dirApplierLock.Unlock()
	delete(dirApplierMap, path)
}

// ClearQuota -- 删除分配给一个目录的配额
func ClearQuota(m mount.Interface, path string) error {
	klog.V(3).Infof("ClearQuota %s", path)
	if !enabledQuotasForMonitoring() {
		return fmt.Errorf("clearQuota called, but quotas disabled")
	}
	quotaLock.Lock()
	defer quotaLock.Unlock()
	poduid, ok := dirPodMap[path]
	if !ok {

		// 因此如果我们找到了配额,就将其删除.
		// 清除配额的过程需要找到一个applier,需要进行清理.
		defer delete(supportsQuotasMap, path)
		defer clearApplier(path)
		return clearQuotaOnDir(m, path)
	}
	_, ok = podQuotaMap[poduid]
	if !ok {
		return fmt.Errorf("clearQuota: No quota available for %s", path)
	}
	projid, err := getQuotaOnDir(m, path)
	if err != nil {
		// Log-and-continue instead of returning an error for now
		// due to unspecified backwards compatibility concerns (a subject to revise)
		klog.V(3).Infof("Attempt to check quota ID %v on dir %s failed: %v", dirQuotaMap[path], path, err)
	}
	if projid != dirQuotaMap[path] {
		return fmt.Errorf("expected quota ID %v on dir %s does not match actual %v", dirQuotaMap[path], path, projid)
	}
	count, ok := podDirCountMap[poduid]
	if count <= 1 || !ok {
		err = clearQuotaOnDir(m, path)
		// This error should be noted; we still need to clean up
		// and otherwise handle in the same way.
		if err != nil {
			klog.V(3).Infof("Unable to clear quota %v %s: %v", dirQuotaMap[path], path, err)
		}
		delete(quotaSizeMap, podQuotaMap[poduid])
		delete(quotaPodMap, podQuotaMap[poduid])
		delete(podDirCountMap, poduid)
		delete(podQuotaMap, poduid)
	} else {
		err = removeProjectID(path, projid)
		podDirCountMap[poduid]--
		klog.V(4).Infof("Not clearing quota for pod %s; still %v dirs outstanding", poduid, podDirCountMap[poduid])
	}
	delete(dirPodMap, path)
	delete(dirQuotaMap, path)
	delete(supportsQuotasMap, path)
	clearApplier(path)
	if err != nil {
		return fmt.Errorf("unable to clear quota for %s: %v", path, err)
	}
	return nil
}

// Assumes that the path has been fully canonicalized
// Breaking this up helps with testing
func detectMountpointInternal(m mount.Interface, path string) (string, error) {
	for path != "" && path != "/" {
		// per k8s.io/mount-utils/mount_linux this detects all but
		// a bind mount from one part of a mount to another.
		// For our purposes that's fine; we simply want the "true"
		// mount point
		//
		// IsNotMountPoint proved much more troublesome; it actually
		// scans the mounts, and when a lot of mount/unmount
		// activity takes place, it is not able to get a consistent
		// view of /proc/self/mounts, causing it to time out and
		// report incorrectly.
		isNotMount, err := m.IsLikelyNotMountPoint(path)
		if err != nil {
			return "/", err
		}
		if !isNotMount {
			return path, nil
		}
		path = filepath.Dir(path)
	}
	return "/", nil
}

// 检测文件系统挂载点
func detectMountpoint(m mount.Interface, path string) (string, error) {
	xpath, err := filepath.Abs(path)
	if err != nil {
		return "/", err
	}
	// 解析任何符号链接后返回路径名.如果路径是相对路径,则结果将相对于当前目录,除非其中一个组件是绝对符号链接.EvalSymlinks在结果上调用Clean函数.
	xpath, err = filepath.EvalSymlinks(xpath)
	if err != nil {
		return "/", err
	}
	if xpath, err = detectMountpointInternal(m, xpath); err == nil {
		return xpath, nil
	}
	return "/", err
}

// getFSInfo Returns mountpoint and backing device
// getFSInfo should cache the mountpoint and backing device for the
// path.
func getFSInfo(m mount.Interface, path string) (string, string, error) {
	mountpointLock.Lock()
	defer mountpointLock.Unlock()

	backingDevLock.Lock()
	defer backingDevLock.Unlock()

	var err error

	mountpoint, okMountpoint := mountpointMap[path]
	if !okMountpoint {
		mountpoint, err = detectMountpoint(m, path)
		if err != nil {
			return "", "", fmt.Errorf("cannot determine mountpoint for %s: %v", path, err)
		}
	}

	backingDev, okBackingDev := backingDevMap[path]
	if !okBackingDev {
		backingDev, err = detectBackingDev(m, mountpoint)
		if err != nil {
			return "", "", fmt.Errorf("cannot determine backing device for %s: %v", path, err)
		}
	}
	mountpointMap[path] = mountpoint
	backingDevMap[path] = backingDev
	return mountpoint, backingDev, nil
}

// Separate the innards for ease of testing
func detectBackingDevInternal(mountpoint string, mounts string) (string, error) {
	file, err := os.Open(mounts)
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		match := common.MountParseRegexp.FindStringSubmatch(scanner.Text())
		if match != nil {
			device := match[1]
			mount := match[2]
			if mount == mountpoint {
				return device, nil
			}
		}
	}
	return "", fmt.Errorf("couldn't find backing device for %s", mountpoint)
}

// detectBackingDev assumes that the mount point provided is valid
func detectBackingDev(_ mount.Interface, mountpoint string) (string, error) {
	return detectBackingDevInternal(mountpoint, common.MountsFile)
}
