/*
Copyright 2022 The Kubernetes Authors.

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

package v1beta1

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/opencontainers/selinux/go-selinux"
	"google.golang.org/grpc"

	core "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	api "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
	v1helper "k8s.io/kubernetes/pkg/apis/core/v1/helper"
	"k8s.io/kubernetes/pkg/kubelet/config"
	"k8s.io/kubernetes/pkg/kubelet/metrics"
	"k8s.io/kubernetes/pkg/kubelet/pluginmanager/cache"
)

// Server interface provides methods for Device plugin registration server.
type Server interface {
	cache.PluginHandler
	Start() error
	Stop() error
	SocketPath() string
}

type server struct {
	socketName string
	socketDir  string
	mutex      sync.Mutex
	wg         sync.WaitGroup
	grpc       *grpc.Server
	rhandler   RegistrationHandler
	chandler   ClientHandler // 当与设备插件建立好链接、断开连接、的钩子
	clients    map[string]Client
}

// Register grpc 服务端提供的功能
func (s *server) Register(ctx context.Context, r *api.RegisterRequest) (*api.Empty, error) {
	klog.InfoS("收到来自具有资源的设备插件的注册请求.", "resourceName", r.ResourceName)
	metrics.DevicePluginRegistrationCount.WithLabelValues(r.ResourceName).Inc()

	if !s.isVersionCompatibleWithPlugin(r.Version) {
		err := fmt.Errorf(errUnsupportedVersion, r.Version, api.SupportedVersions)
		klog.InfoS("来自具有资源的设备插件的注册请求有问题.", "resourceName", r.ResourceName, "err", err)
		return &api.Empty{}, err
	}

	if !v1helper.IsExtendedResourceName(core.ResourceName(r.ResourceName)) {
		err := fmt.Errorf(errInvalidResourceName, r.ResourceName)
		klog.InfoS("来自设备插件的注册请求有问题.", "err", err)
		return &api.Empty{}, err
	}

	if err := s.connectClient(r.ResourceName, filepath.Join(s.socketDir, r.Endpoint)); err != nil {
		klog.InfoS("Error connecting to device plugin client", "err", err)
		return &api.Empty{}, err
	}

	return &api.Empty{}, nil
}

func (s *server) isVersionCompatibleWithPlugin(versions ...string) bool {
	// TODO(vikasc): Currently this is fine as we only have a single supported version. When we do need to support
	// multiple versions in the future, we may need to extend this function to return a supported version.
	// E.g., say kubelet supports v1beta1 and v1beta2, and we get v1alpha1 and v1beta1 from a device plugin,
	// this function should return v1beta1
	// TODO（vikasc）：目前这还可以,因为我们只支持单个版本.当我们将来需要支持多个版本时,可能需要扩展此函数以返回支持的版本.
	// 例如,假设kubelet支持v1beta1和v1beta2,并且我们从设备插件获取到v1alpha1和v1beta1,此函数应该返回v1beta1.
	for _, version := range versions {
		for _, supportedVersion := range api.SupportedVersions {
			if version == supportedVersion {
				return true
			}
		}
	}
	return false
}

func (s *server) visitClients(visit func(r string, c Client)) {
	s.mutex.Lock()
	for r, c := range s.clients {
		s.mutex.Unlock()
		visit(r, c)
		s.mutex.Lock()
	}
	s.mutex.Unlock()
}

// NewServer returns an initialized device plugin registration server.
func NewServer(socketPath string, rh RegistrationHandler, ch ClientHandler) (Server, error) {
	if socketPath == "" || !filepath.IsAbs(socketPath) {
		return nil, fmt.Errorf(errBadSocket+" %s", socketPath)
	}

	dir, name := filepath.Split(socketPath)

	klog.V(2).InfoS("创建设备插件注册服务器.", "version", api.Version, "socket", socketPath)
	s := &server{
		socketName: name,
		socketDir:  dir,
		rhandler:   rh,
		chandler:   ch,
		clients:    make(map[string]Client),
	}

	return s, nil
}

func (s *server) Stop() error {
	s.visitClients(func(r string, c Client) {
		if err := s.disconnectClient(r, c); err != nil {
			klog.InfoS("Error disconnecting device plugin client", "resourceName", r, "err", err)
		}
	})

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.grpc == nil {
		return nil
	}

	s.grpc.Stop()
	s.wg.Wait()
	s.grpc = nil

	return nil
}
func (s *server) SocketPath() string {
	return filepath.Join(s.socketDir, s.socketName)
}
func (s *server) Start() error {
	klog.V(2).InfoS("Starting device plugin registration server")

	if err := os.MkdirAll(s.socketDir, 0750); err != nil {
		klog.ErrorS(err, "Failed to create the device plugin socket directory", "directory", s.socketDir)
		return err
	}

	if selinux.GetEnabled() {
		if err := selinux.SetFileLabel(s.socketDir, config.KubeletPluginsDirSELinuxLabel); err != nil {
			klog.InfoS("非特权容器化插件可能无法正常工作.无法在套接字目录上设置 SELinux 上下文.", "path", s.socketDir, "err", err)
		}
	}

	// For now we leave cleanup of the *entire* directory up to the Handler
	// (even though we should in theory be able to just wipe the whole directory)
	// because the Handler stores its checkpoint file (amongst others) in here.
	// 目前,我们将整个目录的清理工作留给处理程序（尽管理论上我们应该能够只清除整个目录）,因为处理程序在这里存储其检查点文件（以及其他文件）.
	if err := s.rhandler.CleanupPluginDirectory(s.socketDir); err != nil {
		klog.ErrorS(err, "清理设备插件目录失败.", "directory", s.socketDir)
		return err
	}

	ln, err := net.Listen("unix", s.SocketPath())
	if err != nil {
		klog.ErrorS(err, "在启动设备插件注册表时,无法监听套接字.")
		return err
	}

	s.wg.Add(1)
	s.grpc = grpc.NewServer([]grpc.ServerOption{}...)

	api.RegisterRegistrationServer(s.grpc, s)
	go func() {
		defer s.wg.Done()
		s.grpc.Serve(ln)
	}()

	return nil
}
