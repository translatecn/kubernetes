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

package mount

import (
	"fmt"
	"os"
	"time"

	"k8s.io/klog/v2"
)

func CleanupMountWithForce(mountPath string, mounter MounterForceUnmounter, extensiveMountPointCheck bool, umountTimeout time.Duration) error {
	pathExists, pathErr := PathExists(mountPath)
	if !pathExists && pathErr == nil {
		klog.Warningf("Warning: mount cleanup skipped because path does not exist: %v", mountPath)
		return nil
	}
	corruptedMnt := IsCorruptedMnt(pathErr)
	if pathErr != nil && !corruptedMnt {
		return fmt.Errorf("Error checking path: %v", pathErr)
	}

	if corruptedMnt || mounter.canSafelySkipMountPointCheck() {
		klog.V(4).Infof("unmounting %q (corruptedMount: %t, mounterCanSkipMountPointChecks: %t)",
			mountPath, corruptedMnt, mounter.canSafelySkipMountPointCheck())
		if err := mounter.UnmountWithForce(mountPath, umountTimeout); err != nil {
			return err
		}
		return removePath(mountPath)
	}

	notMnt, err := removePathIfNotMountPoint(mountPath, mounter, extensiveMountPointCheck)
	// if mountPath is not a mount point, it's just been removed or there was an error
	if err != nil || notMnt {
		return err
	}

	klog.V(4).Infof("%q is a mountpoint, unmounting", mountPath)
	if err := mounter.UnmountWithForce(mountPath, umountTimeout); err != nil {
		return err
	}

	notMnt, err = removePathIfNotMountPoint(mountPath, mounter, extensiveMountPointCheck)
	// if mountPath is not a mount point, it's either just been removed or there was an error
	if notMnt {
		return err
	}
	// mountPath is still a mount point
	return fmt.Errorf("failed to cleanup mount point %v", mountPath)
}

// removePathIfNotMountPoint verifies if given mountPath is a mount point if not it attempts
// to remove the directory. Returns true and nil if directory was not a mount point and removed.
func removePathIfNotMountPoint(mountPath string, mounter Interface, extensiveMountPointCheck bool) (bool, error) {
	var notMnt bool
	var err error

	if extensiveMountPointCheck {
		notMnt, err = IsNotMountPoint(mounter, mountPath)
	} else {
		notMnt, err = mounter.IsLikelyNotMountPoint(mountPath)
	}

	if err != nil {
		if os.IsNotExist(err) {
			klog.V(4).Infof("%q does not exist", mountPath)
			return true, nil
		}
		return notMnt, err
	}

	if notMnt {
		klog.Warningf("Warning: %q is not a mountpoint, deleting", mountPath)
		return notMnt, os.Remove(mountPath)
	}
	return notMnt, nil
}

// removePath attempts to remove the directory. Returns nil if the directory was removed or does not exist.
func removePath(mountPath string) error {
	klog.V(4).Infof("Warning: deleting path %q", mountPath)
	err := os.Remove(mountPath)
	if os.IsNotExist(err) {
		klog.V(4).Infof("%q does not exist", mountPath)
		return nil
	}
	return err
}

// CleanupMountPoint unmounts the given path and deletes the remaining directory
// if successful. If extensiveMountPointCheck is true IsNotMountPoint will be
// called instead of IsLikelyNotMountPoint. IsNotMountPoint is more expensive
// but properly handles bind mounts within the same fs.
func CleanupMountPoint(mountPath string, mounter Interface, extensiveMountPointCheck bool) error {
	pathExists, pathErr := PathExists(mountPath)
	if !pathExists && pathErr == nil {
		klog.Warningf("Warning: mount cleanup skipped because path does not exist: %v", mountPath)
		return nil
	}
	corruptedMnt := IsCorruptedMnt(pathErr) // 挂载点是否损坏
	if pathErr != nil && !corruptedMnt {
		return fmt.Errorf("error checking path: %v", pathErr)
	}
	return doCleanupMountPoint(mountPath, mounter, extensiveMountPointCheck, corruptedMnt)
}

// 用于卸载给定的路径并在成功后删除剩余的目录.如果extensiveMountPointCheck为true,则调用IsNotMountPoint而不是IsLikelyNotMountPoint.
// IsNotMountPoint更昂贵,但可以正确处理在同一文件系统中的绑定挂载.
// 如果corruptedMnt为true,则意味着mountPath是一个损坏的挂载点,并且将跳过挂载点检查.如果挂载器支持,则也将跳过挂载点检查.
func doCleanupMountPoint(mountPath string, mounter Interface, extensiveMountPointCheck bool, corruptedMnt bool) error {
	if corruptedMnt || mounter.canSafelySkipMountPointCheck() {
		klog.V(4).Infof("unmounting %q (corruptedMount: %t, mounterCanSkipMountPointChecks: %t)", mountPath, corruptedMnt, mounter.canSafelySkipMountPointCheck())
		if err := mounter.Unmount(mountPath); err != nil {
			return err
		}
		return removePath(mountPath)
	}

	notMnt, err := removePathIfNotMountPoint(mountPath, mounter, extensiveMountPointCheck)
	// if mountPath is not a mount point, it's just been removed or there was an error
	if err != nil || notMnt {
		return err
	}

	klog.V(4).Infof("%q is a mountpoint, unmounting", mountPath)
	if err := mounter.Unmount(mountPath); err != nil {
		return err
	}

	notMnt, err = removePathIfNotMountPoint(mountPath, mounter, extensiveMountPointCheck)
	// if mountPath is not a mount point, it's either just been removed or there was an error
	if notMnt {
		return err
	}
	// mountPath is still a mount point
	return fmt.Errorf("failed to cleanup mount point %v", mountPath)
}
