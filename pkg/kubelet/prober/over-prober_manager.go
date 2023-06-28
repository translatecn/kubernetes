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

package prober

import (
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/record"
	"k8s.io/component-base/metrics"
	"k8s.io/klog/v2"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/prober/results"
	"k8s.io/kubernetes/pkg/kubelet/status"
	"k8s.io/utils/clock"
)

// ProberResults stores the cumulative number of a probe by result as prometheus metrics.
var ProberResults = metrics.NewCounterVec(
	&metrics.CounterOpts{
		Subsystem:      "prober",
		Name:           "probe_total",
		Help:           "按结果统计容器的存活探针、就绪探针或启动探针的累计次数.",
		StabilityLevel: metrics.ALPHA,
	},
	[]string{"probe_type",
		"result",
		"container",
		"pod",
		"namespace",
		"pod_uid"},
)

// ProberDuration stores the duration of a successful probe lifecycle by result as prometheus metrics.
var ProberDuration = metrics.NewHistogramVec(
	&metrics.HistogramOpts{
		Subsystem:      "prober",
		Name:           "probe_duration_seconds",
		Help:           "探测响应时间",
		StabilityLevel: metrics.ALPHA,
	},
	[]string{"probe_type",
		"container",
		"pod",
		"namespace"},
)

// Manager manages pod probing. It creates a probe "worker" for every container that specifies a
// probe (AddPod). The worker periodically probes its assigned container and caches the results. The
// manager use the cached probe results to set the appropriate Ready state in the PodStatus when
// requested (UpdatePodStatus). Updating probe parameters is not currently supported.
type Manager interface {
	// AddPod creates new probe workers for every container probe. This should be called for every
	// pod created.
	AddPod(pod *v1.Pod)

	// StopLivenessAndStartup handles stopping liveness and startup probes during termination.
	StopLivenessAndStartup(pod *v1.Pod)

	// RemovePod handles cleaning up the removed pod state, including terminating probe workers and
	// deleting cached results.
	RemovePod(pod *v1.Pod)
	CleanupPods(desiredPods map[types.UID]sets.Empty) // 清理不在desiredPods 里的探测worker.  desiredPods[运行中,可能在运行的]

	// UpdatePodStatus modifies the given PodStatus with the appropriate Ready state for each
	// container based on container running status, cached probe results and worker states.
	UpdatePodStatus(types.UID, *v1.PodStatus)
}

type manager struct {
	workers map[probeKey]*worker // 工作中的 容器探测 worker
	// Lock for accessing & mutating workers
	workerLock sync.RWMutex

	// The statusManager cache provides pod IP and container IDs for probing.
	statusManager status.Manager

	readinessManager results.Manager // readiness 探测器
	livenessManager  results.Manager // liveness 探测器
	startupManager   results.Manager // startup 探测器

	// prober executes the probe actions.
	prober *prober
	start  time.Time
}

func NewManager(
	statusManager status.Manager,
	livenessManager results.Manager,
	readinessManager results.Manager,
	startupManager results.Manager,
	runner kubecontainer.CommandRunner,
	recorder record.EventRecorder) Manager {

	prober := newProber(runner, recorder)
	return &manager{
		statusManager:    statusManager,
		prober:           prober,
		readinessManager: readinessManager,
		livenessManager:  livenessManager,
		startupManager:   startupManager, // set
		workers:          make(map[probeKey]*worker),
		start:            clock.RealClock{}.Now(),
	}
}

// Key uniquely identifying container probes
type probeKey struct {
	podUID        types.UID
	containerName string
	probeType     probeType
}

type probeType int

const (
	liveness probeType = iota
	readiness
	startup

	probeResultSuccessful string = "successful"
	probeResultFailed     string = "failed"
	probeResultUnknown    string = "unknown"
)

// For debugging.
func (t probeType) String() string {
	switch t {
	case readiness:
		return "Readiness"
	case liveness:
		return "Liveness"
	case startup:
		return "Startup"
	default:
		return "UNKNOWN"
	}
}

func (m *manager) AddPod(pod *v1.Pod) { // ✅
	m.workerLock.Lock()
	defer m.workerLock.Unlock()

	key := probeKey{podUID: pod.UID}
	for _, c := range pod.Spec.Containers {
		key.containerName = c.Name

		if c.StartupProbe != nil {
			key.probeType = startup
			if _, ok := m.workers[key]; ok {
				klog.V(8).ErrorS(nil, "Startup probe already exists for container",
					"pod", klog.KObj(pod), "containerName", c.Name)
				return
			}
			w := newWorker(m, startup, pod, c)
			m.workers[key] = w
			go w.run()
		}

		if c.ReadinessProbe != nil {
			key.probeType = readiness
			if _, ok := m.workers[key]; ok {
				klog.V(8).ErrorS(nil, "Readiness probe already exists for container",
					"pod", klog.KObj(pod), "containerName", c.Name)
				return
			}
			w := newWorker(m, readiness, pod, c)
			m.workers[key] = w
			go w.run()
		}

		if c.LivenessProbe != nil {
			key.probeType = liveness
			if _, ok := m.workers[key]; ok {
				klog.V(8).ErrorS(nil, "Liveness probe already exists for container",
					"pod", klog.KObj(pod), "containerName", c.Name)
				return
			}
			w := newWorker(m, liveness, pod, c)
			m.workers[key] = w
			go w.run()
		}
	}
}

func (m *manager) RemovePod(pod *v1.Pod) {
	m.workerLock.RLock()
	defer m.workerLock.RUnlock()

	key := probeKey{podUID: pod.UID}
	for _, c := range pod.Spec.Containers {
		key.containerName = c.Name
		for _, probeType := range [...]probeType{readiness, liveness, startup} {
			key.probeType = probeType
			if worker, ok := m.workers[key]; ok {
				worker.stop()
			}
		}
	}
}

func (m *manager) StopLivenessAndStartup(pod *v1.Pod) {
	m.workerLock.RLock()
	defer m.workerLock.RUnlock()

	key := probeKey{podUID: pod.UID}
	for _, c := range pod.Spec.Containers {
		key.containerName = c.Name
		for _, probeType := range [...]probeType{liveness, startup} {
			key.probeType = probeType
			if worker, ok := m.workers[key]; ok {
				worker.stop()
			}
		}
	}
}

func (m *manager) CleanupPods(desiredPods map[types.UID]sets.Empty) {
	m.workerLock.RLock()
	defer m.workerLock.RUnlock()

	for key, worker := range m.workers {
		if _, ok := desiredPods[key.podUID]; !ok {
			worker.stop()
		}
	}
}

func (m *manager) getWorker(podUID types.UID, containerName string, probeType probeType) (*worker, bool) {
	m.workerLock.RLock()
	defer m.workerLock.RUnlock()
	worker, ok := m.workers[probeKey{podUID, containerName, probeType}]
	return worker, ok
}

// Called by the worker after exiting.
func (m *manager) removeWorker(podUID types.UID, containerName string, probeType probeType) {
	m.workerLock.Lock()
	defer m.workerLock.Unlock()
	delete(m.workers, probeKey{podUID, containerName, probeType})
}

// workerCount returns the total number of probe workers. For testing.
func (m *manager) workerCount() int {
	m.workerLock.RLock()
	defer m.workerLock.RUnlock()
	return len(m.workers)
}

func (m *manager) UpdatePodStatus(podUID types.UID, podStatus *v1.PodStatus) {
	for i, c := range podStatus.ContainerStatuses {
		var started bool
		if c.State.Running == nil {
			started = false
		} else if result, ok := m.startupManager.Get(kubecontainer.ParseContainerID(c.ContainerID)); ok {
			started = result == results.Success
		} else {
			// The check whether there is a probe which hasn't run yet.
			_, exists := m.getWorker(podUID, c.Name, startup)
			started = !exists
		}
		podStatus.ContainerStatuses[i].Started = &started

		if started {
			var ready bool
			if c.State.Running == nil {
				ready = false
			} else if result, ok := m.readinessManager.Get(kubecontainer.ParseContainerID(c.ContainerID)); ok && result == results.Success {
				ready = true
			} else {
				// The check whether there is a probe which hasn't run yet.
				w, exists := m.getWorker(podUID, c.Name, readiness)
				ready = !exists // no readinessProbe -> always ready
				if exists {
					// Trigger an immediate run of the readinessProbe to update ready state
					select {
					case w.manualTriggerCh <- struct{}{}:
					default: // Non-blocking.
						klog.InfoS("探测失败", "probe", w.probeType.String())
					}
				}
			}
			podStatus.ContainerStatuses[i].Ready = ready
		}
	}
	// init containers are ready if they have exited with success or if a readiness probe has
	// succeeded.
	for i, c := range podStatus.InitContainerStatuses {
		var ready bool
		if c.State.Terminated != nil && c.State.Terminated.ExitCode == 0 {
			ready = true
		}
		podStatus.InitContainerStatuses[i].Ready = ready
	}
}
