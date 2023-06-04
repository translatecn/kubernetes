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

//go:generate mockgen -destination=testing/mock_manager.go -package=testing -build_flags=-mod=mod . Manager
package pod

import (
	"sync"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/kubernetes/pkg/kubelet/configmap"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/metrics"
	"k8s.io/kubernetes/pkg/kubelet/secret"
	kubetypes "k8s.io/kubernetes/pkg/kubelet/types"
)

// Manager 存储和管理对 Pod 的访问,维护静态 Pod 和镜像 Pod 之间的映射关系.
//
// kubelet 从三个来源发现 Pod 更新：文件、HTTP 和 API 服务器.来自非 API 服务器源的 Pod 称为静态 Pod,API 服务器不知道静态 Pod 的存在.
// 为了监视这种 Pod 的状态,kubelet 通过 API 服务器为每个静态 Pod 创建一个镜像 Pod.
//
// 镜像 Pod 与其静态对应项具有相同的 Pod 全名（名称和命名空间）,尽管元数据（如 UID 等）不同.
// 通过利用 kubelet 使用 Pod 全名报告 Pod 状态的事实,镜像 Pod 的状态始终反映静态 Pod 的实际状态.
// 当删除静态 Pod 时,相关的孤立的镜像 Pod 也将被删除.
//
// Manager 用于管理静态 Pod 和镜像 Pod 之间的映射关系,并确保 kubelet 可以监视静态 Pod 的状态.
type Manager interface {
	GetPods() []*v1.Pod                                     // 返回绑定到 kubelet 的常规 Pod 及其规格.
	GetPodByFullName(podFullName string) (*v1.Pod, bool)    // 完整名称匹配的（非镜像）Pod,以及是否找到了该 Pod.
	GetPodByName(namespace, name string) (*v1.Pod, bool)    // 提供与命名空间和名称匹配的（非镜像）Pod,以及是否找到了该 Pod.
	GetPodByUID(types.UID) (*v1.Pod, bool)                  // 提供与 Pod UID 匹配的（非镜像）Pod,以及是否找到了该 Pod.
	GetPodByMirrorPod(*v1.Pod) (*v1.Pod, bool)              // 返回给定镜像 Pod 的静态 Pod,以及该静态 Pod 是否已知于 Pod 管理器.
	GetMirrorPodByPod(*v1.Pod) (*v1.Pod, bool)              // 返回给定静态 Pod 的镜像 Pod,以及该镜像 Pod 是否已知于 Pod 管理器.
	GetPodsAndMirrorPods() ([]*v1.Pod, []*v1.Pod)           // 返回一般和镜像 Pod.
	SetPods(pods []*v1.Pod)                                 // 用新 Pod 替换内部 Pod.它目前仅用于测试.
	AddPod(pod *v1.Pod)                                     // 将给定的 Pod 添加到管理器中.
	UpdatePod(pod *v1.Pod)                                  // 在管理器中更新给定的 Pod.
	DeletePod(pod *v1.Pod)                                  // 从管理器中删除给定的 Pod.对于镜像 Pod,这意味着删除与镜像 Pod 相关的映射.对于非镜像 Pod,这意味着从所有非镜像 Pod 的索引中删除.
	GetOrphanedMirrorPodNames() []string                    // 返回孤立的镜像 Pod 的名称.
	TranslatePodUID(uid types.UID) kubetypes.ResolvedPodUID // 返回 Pod 的实际 UID.如果 UID 属于镜像 Pod,则返回其静态 Pod 的 UID.否则,返回原始 UID.
	GetUIDTranslations() (
		podToMirror map[kubetypes.ResolvedPodUID]kubetypes.MirrorPodUID,
		mirrorToPod map[kubetypes.MirrorPodUID]kubetypes.ResolvedPodUID,
	) // 返回静态 Pod UID 到镜像 Pod UID 和镜像 Pod UID 到静态 Pod UID 的映射.
	IsMirrorPodOf(mirrorPod, pod *v1.Pod) bool // 如果 mirrorPod 是 pod 的正确表示,则返回 true;否则返回 false.
	MirrorClient
}

// basicManager 是一个功能性的 Manager.
// 所有字段都是只读的,可以通过调用 SetPods、AddPod、UpdatePod 或 DeletePod 来更新.
type basicManager struct {
	lock                sync.RWMutex
	podByUID            map[kubetypes.ResolvedPodUID]*v1.Pod                // 从 Pod UID 到 Pod 的映射,用于索引常规 Pod.
	mirrorPodByUID      map[kubetypes.MirrorPodUID]*v1.Pod                  // Pod UID 到镜像 Pod 的映射,用于索引镜像 Pod.
	podByFullName       map[string]*v1.Pod                                  // 从 Pod 全名到 Pod 的映射,用于轻松访问 Pod.
	mirrorPodByFullName map[string]*v1.Pod                                  // 从 Pod 全名到镜像 Pod 的映射,用于轻松访问镜像 Pod.
	translationByUID    map[kubetypes.MirrorPodUID]kubetypes.ResolvedPodUID // 从镜像 Pod UID 到静态 Pod UID 的映射,用于维护静态 Pod 和镜像 Pod 之间的映射关系.
	secretManager       secret.Manager                                      // 用于管理 Secret.
	configMapManager    configmap.Manager                                   // 用于管理 ConfigMap.
	MirrorClient                                                            // 用于创建和删除镜像 Pod.
}

// NewBasicPodManager returns a functional Manager.
func NewBasicPodManager(client MirrorClient, secretManager secret.Manager, configMapManager configmap.Manager) Manager {
	pm := &basicManager{}
	pm.secretManager = secretManager
	pm.configMapManager = configMapManager
	pm.MirrorClient = client
	pm.SetPods(nil)
	return pm
}

// SetPods Set the internal pods based on the new pods.
func (pm *basicManager) SetPods(newPods []*v1.Pod) {
	pm.lock.Lock()
	defer pm.lock.Unlock()

	pm.podByUID = make(map[kubetypes.ResolvedPodUID]*v1.Pod)
	pm.podByFullName = make(map[string]*v1.Pod)
	pm.mirrorPodByUID = make(map[kubetypes.MirrorPodUID]*v1.Pod)
	pm.mirrorPodByFullName = make(map[string]*v1.Pod)
	pm.translationByUID = make(map[kubetypes.MirrorPodUID]kubetypes.ResolvedPodUID)

	pm.updatePodsInternal(newPods...)
}

func (pm *basicManager) AddPod(pod *v1.Pod) {
	pm.UpdatePod(pod)
}

func (pm *basicManager) UpdatePod(pod *v1.Pod) {
	pm.lock.Lock()
	defer pm.lock.Unlock()
	pm.updatePodsInternal(pod)
}

func updateMetrics(oldPod, newPod *v1.Pod) {
	var numEC int
	if oldPod != nil {
		numEC -= len(oldPod.Spec.EphemeralContainers)
	}
	if newPod != nil {
		numEC += len(newPod.Spec.EphemeralContainers)
	}
	if numEC != 0 {
		metrics.ManagedEphemeralContainers.Add(float64(numEC))
	}
}

// 替换管理器当前状态下的给定pod,更新各种索引.假定调用方持有锁.
func (pm *basicManager) updatePodsInternal(pods ...*v1.Pod) {
	for _, pod := range pods {
		podFullName := kubecontainer.GetPodFullName(pod)
		// This logic relies on a static pod and its mirror to have the same name.
		// It is safe to type convert here due to the IsMirrorPod guard.
		if kubetypes.IsMirrorPod(pod) {
			mirrorPodUID := kubetypes.MirrorPodUID(pod.UID)
			pm.mirrorPodByUID[mirrorPodUID] = pod
			pm.mirrorPodByFullName[podFullName] = pod
			if p, ok := pm.podByFullName[podFullName]; ok {
				pm.translationByUID[mirrorPodUID] = kubetypes.ResolvedPodUID(p.UID)
			}
		} else {
			resolvedPodUID := kubetypes.ResolvedPodUID(pod.UID)
			updateMetrics(pm.podByUID[resolvedPodUID], pod)
			pm.podByUID[resolvedPodUID] = pod
			pm.podByFullName[podFullName] = pod
			if mirror, ok := pm.mirrorPodByFullName[podFullName]; ok {
				pm.translationByUID[kubetypes.MirrorPodUID(mirror.UID)] = resolvedPodUID
			}
		}
	}
}

func (pm *basicManager) DeletePod(pod *v1.Pod) {
	updateMetrics(pod, nil)
	pm.lock.Lock()
	defer pm.lock.Unlock()
	podFullName := kubecontainer.GetPodFullName(pod)
	// It is safe to type convert here due to the IsMirrorPod guard.
	if kubetypes.IsMirrorPod(pod) {
		mirrorPodUID := kubetypes.MirrorPodUID(pod.UID)
		delete(pm.mirrorPodByUID, mirrorPodUID)
		delete(pm.mirrorPodByFullName, podFullName)
		delete(pm.translationByUID, mirrorPodUID)
	} else {
		delete(pm.podByUID, kubetypes.ResolvedPodUID(pod.UID))
		delete(pm.podByFullName, podFullName)
	}
}

func (pm *basicManager) GetPods() []*v1.Pod {
	pm.lock.RLock()
	defer pm.lock.RUnlock()
	return podsMapToPods(pm.podByUID)
}

func (pm *basicManager) GetPodsAndMirrorPods() ([]*v1.Pod, []*v1.Pod) {
	pm.lock.RLock()
	defer pm.lock.RUnlock()
	pods := podsMapToPods(pm.podByUID)                         // 转数组
	mirrorPods := mirrorPodsMapToMirrorPods(pm.mirrorPodByUID) // 转数组
	return pods, mirrorPods
}

func (pm *basicManager) GetPodByUID(uid types.UID) (*v1.Pod, bool) {
	pm.lock.RLock()
	defer pm.lock.RUnlock()
	pod, ok := pm.podByUID[kubetypes.ResolvedPodUID(uid)] // Safe conversion, map only holds non-mirrors.
	return pod, ok
}

func (pm *basicManager) GetPodByName(namespace, name string) (*v1.Pod, bool) {
	podFullName := kubecontainer.BuildPodFullName(name, namespace)
	return pm.GetPodByFullName(podFullName)
}

func (pm *basicManager) GetPodByFullName(podFullName string) (*v1.Pod, bool) {
	pm.lock.RLock()
	defer pm.lock.RUnlock()
	pod, ok := pm.podByFullName[podFullName]
	return pod, ok
}

func (pm *basicManager) TranslatePodUID(uid types.UID) kubetypes.ResolvedPodUID {
	// It is safe to type convert to a resolved UID because type conversion is idempotent.
	if uid == "" {
		return kubetypes.ResolvedPodUID(uid)
	}

	pm.lock.RLock()
	defer pm.lock.RUnlock()
	if translated, ok := pm.translationByUID[kubetypes.MirrorPodUID(uid)]; ok {
		return translated
	}
	return kubetypes.ResolvedPodUID(uid)
}

func (pm *basicManager) GetUIDTranslations() (podToMirror map[kubetypes.ResolvedPodUID]kubetypes.MirrorPodUID,
	mirrorToPod map[kubetypes.MirrorPodUID]kubetypes.ResolvedPodUID) {
	pm.lock.RLock()
	defer pm.lock.RUnlock()

	podToMirror = make(map[kubetypes.ResolvedPodUID]kubetypes.MirrorPodUID, len(pm.translationByUID))
	mirrorToPod = make(map[kubetypes.MirrorPodUID]kubetypes.ResolvedPodUID, len(pm.translationByUID))
	// Insert empty translation mapping for all static pods.
	for uid, pod := range pm.podByUID {
		if !kubetypes.IsStaticPod(pod) {
			continue
		}
		podToMirror[uid] = ""
	}
	// Fill in translations. Notice that if there is no mirror pod for a
	// static pod, its uid will be translated into empty string "". This
	// is WAI, from the caller side we can know that the static pod doesn't
	// have a corresponding mirror pod instead of using static pod uid directly.
	for k, v := range pm.translationByUID {
		mirrorToPod[k] = v
		podToMirror[v] = k
	}
	return podToMirror, mirrorToPod
}

func (pm *basicManager) GetOrphanedMirrorPodNames() []string {
	pm.lock.RLock()
	defer pm.lock.RUnlock()
	var podFullNames []string
	for podFullName := range pm.mirrorPodByFullName {
		if _, ok := pm.podByFullName[podFullName]; !ok {
			podFullNames = append(podFullNames, podFullName)
		}
	}
	return podFullNames
}

func (pm *basicManager) IsMirrorPodOf(mirrorPod, pod *v1.Pod) bool {
	// Check name and namespace first.
	if pod.Name != mirrorPod.Name || pod.Namespace != mirrorPod.Namespace {
		return false
	}
	hash, ok := getHashFromMirrorPod(mirrorPod)
	if !ok {
		return false
	}
	return hash == getPodHash(pod)
}

func podsMapToPods(UIDMap map[kubetypes.ResolvedPodUID]*v1.Pod) []*v1.Pod {
	pods := make([]*v1.Pod, 0, len(UIDMap))
	for _, pod := range UIDMap {
		pods = append(pods, pod)
	}
	return pods
}

func mirrorPodsMapToMirrorPods(UIDMap map[kubetypes.MirrorPodUID]*v1.Pod) []*v1.Pod {
	pods := make([]*v1.Pod, 0, len(UIDMap))
	for _, pod := range UIDMap {
		pods = append(pods, pod)
	}
	return pods
}

func (pm *basicManager) GetMirrorPodByPod(pod *v1.Pod) (*v1.Pod, bool) {
	pm.lock.RLock()
	defer pm.lock.RUnlock()
	mirrorPod, ok := pm.mirrorPodByFullName[kubecontainer.GetPodFullName(pod)]
	return mirrorPod, ok
}

func (pm *basicManager) GetPodByMirrorPod(mirrorPod *v1.Pod) (*v1.Pod, bool) {
	pm.lock.RLock()
	defer pm.lock.RUnlock()
	pod, ok := pm.podByFullName[kubecontainer.GetPodFullName(mirrorPod)]
	return pod, ok
}
