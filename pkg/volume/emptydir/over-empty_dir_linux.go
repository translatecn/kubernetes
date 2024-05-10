//go:build linux
// +build linux

/*
Copyright 2015 The Kubernetes Authors.

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

package emptydir

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/klog/v2"
	"k8s.io/mount-utils"

	"k8s.io/api/core/v1"
)

// tmpfs挂载的类型号,由Linux定义.
const (
	linuxTmpfsMagic     = 0x01021994 // Linux内核中用于标识tmpfs文件系统的魔数（magic number）,它是一个无符号整数常量.
	linuxHugetlbfsMagic = 0x958458f6 // 用于标识Hugetlbfs文件系统的魔数
)

// realMountDetector implements mountDetector in terms of syscalls.
type realMountDetector struct {
	mounter mount.Interface
}

// getPageSize obtains page size from the 'pagesize' mount option of the
// mounted volume
func getPageSize(path string, mounter mount.Interface) (*resource.Quantity, error) {
	// Get mount point data for the path
	mountPoints, err := mounter.List()
	if err != nil {
		return nil, fmt.Errorf("error listing mount points: %v", err)
	}
	// Find mount point for the path
	mountPoint, err := func(mps []mount.MountPoint, mpPath string) (*mount.MountPoint, error) {
		for _, mp := range mps {
			if mp.Path == mpPath {
				return &mp, nil
			}
		}
		return nil, fmt.Errorf("mount point for %s not found", mpPath)
	}(mountPoints, path)
	if err != nil {
		return nil, err
	}
	// Get page size from the 'pagesize' option value
	for _, opt := range mountPoint.Opts {
		opt = strings.TrimSpace(opt)
		prefix := "pagesize="
		if strings.HasPrefix(opt, prefix) {
			// NOTE: Adding suffix 'i' as result should be comparable with a medium size.
			// pagesize mount option is specified without a suffix,
			// e.g. pagesize=2M or pagesize=1024M for x86 CPUs
			trimmedOpt := strings.TrimPrefix(opt, prefix)
			if !strings.HasSuffix(trimmedOpt, "i") {
				trimmedOpt = trimmedOpt + "i"
			}
			pageSize, err := resource.ParseQuantity(trimmedOpt)
			if err != nil {
				return nil, fmt.Errorf("error getting page size from '%s' mount option: %v", opt, err)
			}
			return &pageSize, nil
		}
	}
	return nil, fmt.Errorf("no pagesize option specified for %s mount", mountPoint.Path)
}

// GetMountMedium 这段代码的作用是确定给定路径由什么类型的介质支持,并且该路径是否是挂载点.
// 例如,如果返回值为(v1.StorageMediumMemory, false, nil),则调用者知道该路径在内存文件系统上（Linux上的tmpfs）,但不是该tmpfs的根挂载点.
func (m *realMountDetector) GetMountMedium(path string, requestedMedium v1.StorageMedium) (v1.StorageMedium, bool, *resource.Quantity, error) {
	klog.V(5).Infof("正在确定给定路径的挂载介质 %v", path)
	notMnt, err := m.mounter.IsLikelyNotMountPoint(path) // 与父目录的设备进行对比
	if err != nil {
		return v1.StorageMediumDefault, false, nil, fmt.Errorf("IsLikelyNotMountPoint(%q): %v", path, err)
	}

	buf := unix.Statfs_t{}
	if err := unix.Statfs(path, &buf); err != nil {
		return v1.StorageMediumDefault, false, nil, fmt.Errorf("statfs(%q): %v", path, err)
	}

	klog.V(3).Infof("Statfs_t of %v: %+v", path, buf)

	if buf.Type == linuxTmpfsMagic {
		return v1.StorageMediumMemory, !notMnt, nil, nil
	} else if int64(buf.Type) == linuxHugetlbfsMagic {
		// Skip page size detection if requested medium doesn't have size specified
		// 如果请求的介质没有指定大小,则跳过页面大小检测.
		if requestedMedium == v1.StorageMediumHugePages {
			return v1.StorageMediumHugePages, !notMnt, nil, nil
		}
		// Get page size for the volume mount
		pageSize, err := getPageSize(path, m.mounter)
		if err != nil {
			return v1.StorageMediumHugePages, !notMnt, nil, err
		}
		return v1.StorageMediumHugePages, !notMnt, pageSize, nil
	}
	return v1.StorageMediumDefault, !notMnt, nil, nil
}

// Statfs_t是一个结构体类型,用于保存文件系统的统计信息.它包含以下字段：
//
//- Type：文件系统类型.
//- Bsize：块大小（字节）.
//- Blocks：文件系统总块数.
//- Bfree：文件系统可用块数.
//- Bavail：非超级用户可用块数.
//- Files：文件系统中的文件节点总数.
//- Ffree：文件系统中可用的文件节点数.
//- Fsid：文件系统标识.
//- Namelen：文件名最大长度.
//- Frsize：片段大小（字节）.
//- Flags：文件系统标志.
//- Spare：保留字段.
