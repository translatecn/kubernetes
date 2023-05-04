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
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/component-base/metrics"
	"k8s.io/klog/v2"
	podutil "k8s.io/kubernetes/pkg/api/v1/pod"
	"k8s.io/kubernetes/pkg/apis/apps"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/prober/results"
)

// worker handles the periodic probing of its assigned container. Each worker has a go-routine
// associated with it which runs the probe loop until the container permanently terminates, or the
// stop channel is closed. The worker uses the probe Manager's statusManager to get up-to-date
// container IDs.
type worker struct {
	// Channel for stopping the probe.
	stopCh chan struct{}

	// Channel for triggering the probe manually.
	manualTriggerCh chan struct{}

	// The pod containing this probe (read-only)
	pod *v1.Pod

	// The container to probe (read-only)
	container v1.Container

	// Describes the probe configuration (read-only)
	spec                                 *v1.Probe
	probeType                            probeType
	initialValue                         results.Result            // 初始延迟期间的探测默认值
	resultsManager                       results.Manager           // 存储 这个worker的结果，具体可以是 startupManager、readinessManager、livenessManager
	probeManager                         *manager                  //
	containerID                          kubecontainer.ContainerID // 此worker的最后一个已知容器ID。
	lastResult                           results.Result            //
	resultRun                            int                       // 当前状态，持续检测了多少次
	onHold                               bool                      // 如何设置了，跳过本次探测
	proberResultsSuccessfulMetricLabels  metrics.Labels
	proberResultsFailedMetricLabels      metrics.Labels
	proberResultsUnknownMetricLabels     metrics.Labels
	proberDurationSuccessfulMetricLabels metrics.Labels
	proberDurationUnknownMetricLabels    metrics.Labels
}

// Creates and starts a new probe worker.
func newWorker(m *manager, probeType probeType, pod *v1.Pod, container v1.Container) *worker {

	w := &worker{
		stopCh:          make(chan struct{}, 1), // Buffer so stop() can be non-blocking.
		manualTriggerCh: make(chan struct{}, 1), // Buffer so prober_manager can do non-blocking calls to doProbe.
		pod:             pod,
		container:       container,
		probeType:       probeType,
		probeManager:    m,
	}

	switch probeType {
	case readiness:
		w.spec = container.ReadinessProbe
		w.resultsManager = m.readinessManager
		w.initialValue = results.Failure
	case liveness:
		w.spec = container.LivenessProbe
		w.resultsManager = m.livenessManager
		w.initialValue = results.Success
	case startup:
		w.spec = container.StartupProbe
		w.resultsManager = m.startupManager
		w.initialValue = results.Unknown
	}

	podName := getPodLabelName(w.pod)

	basicMetricLabels := metrics.Labels{
		"probe_type": w.probeType.String(),
		"container":  w.container.Name,
		"pod":        podName,
		"namespace":  w.pod.Namespace,
		"pod_uid":    string(w.pod.UID),
	}

	proberDurationLabels := metrics.Labels{
		"probe_type": w.probeType.String(),
		"container":  w.container.Name,
		"pod":        podName,
		"namespace":  w.pod.Namespace,
	}

	w.proberResultsSuccessfulMetricLabels = deepCopyPrometheusLabels(basicMetricLabels)
	w.proberResultsSuccessfulMetricLabels["result"] = probeResultSuccessful

	w.proberResultsFailedMetricLabels = deepCopyPrometheusLabels(basicMetricLabels)
	w.proberResultsFailedMetricLabels["result"] = probeResultFailed

	w.proberResultsUnknownMetricLabels = deepCopyPrometheusLabels(basicMetricLabels)
	w.proberResultsUnknownMetricLabels["result"] = probeResultUnknown

	w.proberDurationSuccessfulMetricLabels = deepCopyPrometheusLabels(proberDurationLabels)
	w.proberDurationUnknownMetricLabels = deepCopyPrometheusLabels(proberDurationLabels)

	return w
}

func (w *worker) run() {
	ctx := context.Background()
	probeTickerPeriod := time.Duration(w.spec.PeriodSeconds) * time.Second

	if probeTickerPeriod > time.Since(w.probeManager.start) {
		// 当 kubelet 重新启动时，探针可能会在短时间内连续启动，导致负载过大或者产生其他问题。
		// 为了避免这种情况，需要让 worker 在一定时间内随机等待一段时间，然后再进行探测。这个等待时间是 tickerPeriod 的随机部分，用于平滑探针的启动。
		time.Sleep(time.Duration(rand.Float64() * float64(probeTickerPeriod)))
	}

	probeTicker := time.NewTicker(probeTickerPeriod)

	defer func() {
		// Clean up.
		probeTicker.Stop()
		if !w.containerID.IsEmpty() {
			w.resultsManager.Remove(w.containerID)
		}

		w.probeManager.removeWorker(w.pod.UID, w.container.Name, w.probeType)
		ProberResults.Delete(w.proberResultsSuccessfulMetricLabels)
		ProberResults.Delete(w.proberResultsFailedMetricLabels)
		ProberResults.Delete(w.proberResultsUnknownMetricLabels)
		ProberDuration.Delete(w.proberDurationSuccessfulMetricLabels)
		ProberDuration.Delete(w.proberDurationUnknownMetricLabels)
	}()

probeLoop:
	for w.doProbe(ctx) {
		// Wait for next probe tick.
		select {
		case <-w.stopCh:
			break probeLoop
		case <-probeTicker.C:
		case <-w.manualTriggerCh:
			// continue
		}
	}
}

// stop stops the probe worker. The worker handles cleanup and removes itself from its manager.
// It is safe to call stop multiple times.
func (w *worker) stop() {
	select {
	case w.stopCh <- struct{}{}:
	default: // Non-blocking.
	}
}

// 对容器进行一次探测并记录结果。告诉worker是否应该继续。
func (w *worker) doProbe(ctx context.Context) (keepGoing bool) {
	defer func() { recover() }() // Actually eat panics (HandleCrash takes care of logging)
	defer runtime.HandleCrash(func(_ interface{}) { keepGoing = true })

	startTime := time.Now()
	status, ok := w.probeManager.statusManager.GetPodStatus(w.pod.UID)
	if !ok {
		// Either the pod has not been created yet, or it was already deleted.
		klog.V(3).InfoS("No status for pod", "pod", klog.KObj(w.pod))
		return true
	}

	// Worker should terminate if pod is terminated.
	if status.Phase == v1.PodFailed || status.Phase == v1.PodSucceeded {
		klog.V(3).InfoS("Pod is terminated, exiting probe worker",
			"pod", klog.KObj(w.pod), "phase", status.Phase)
		return false
	}

	c, ok := podutil.GetContainerStatus(status.ContainerStatuses, w.container.Name)
	if !ok || len(c.ContainerID) == 0 {
		// Either the container has not been created yet, or it was deleted.
		klog.V(3).InfoS("Probe target container not found",
			"pod", klog.KObj(w.pod), "containerName", w.container.Name)
		return true // Wait for more information.
	}
	// 比如说，某个pod 重建了 退出码不是0
	if w.containerID.String() != c.ContainerID { // 判断是不是启动了一个新的容器
		if !w.containerID.IsEmpty() {
			w.resultsManager.Remove(w.containerID)
		}
		w.containerID = kubecontainer.ParseContainerID(c.ContainerID)
		w.resultsManager.Set(w.containerID, w.initialValue, w.pod)
		// 我们有一个新的容器;继续探索。
		w.onHold = false
	}

	if w.onHold {
		// worker 被搁置，直到有一个新的container
		return true
	}

	if c.State.Running == nil {
		klog.V(3).InfoS("探测到未运行的容器", "pod", klog.KObj(w.pod), "containerName", w.container.Name)
		if !w.containerID.IsEmpty() {
			w.resultsManager.Set(w.containerID, results.Failure, w.pod)
		}
		// Abort if the container will not be restarted.
		return c.State.Terminated == nil || w.pod.Spec.RestartPolicy != v1.RestartPolicyNever
	}

	// Graceful shutdown of the pod.
	if w.pod.ObjectMeta.DeletionTimestamp != nil && (w.probeType == liveness || w.probeType == startup) {
		klog.V(3).InfoS("请求删除Pod，将探测结果设置为成功", "probeType", w.probeType, "pod", klog.KObj(w.pod), "containerName", w.container.Name)
		if w.probeType == startup {
			klog.InfoS("在容器完全启动之前请求删除Pod", "pod", klog.KObj(w.pod), "containerName", w.container.Name)
		}
		// Set a last result to ensure quiet shutdown.
		w.resultsManager.Set(w.containerID, results.Success, w.pod)
		// Stop probing at this point.
		return false
	}

	// Probe disabled for InitialDelaySeconds.
	if int32(time.Since(c.State.Running.StartedAt.Time).Seconds()) < w.spec.InitialDelaySeconds {
		return true
	}

	if c.Started != nil && *c.Started {
		// 一旦容器启动，停止 探测 启动。
		// 我们让它继续运行，以确保它可以为重启的容器工作。
		if w.probeType == startup {
			return true
		}
	} else {
		// 禁止其他探测，直到 启动
		if w.probeType != startup {
			return true
		}
	}

	// Note, exec probe does NOT have access to pod environment variables or downward API
	result, err := w.probeManager.prober.probe(ctx, w.probeType, w.pod, status, w.container, w.containerID)
	if err != nil {
		// Prober error, throw away the result.
		return true
	}

	switch result {
	case results.Success:
		ProberResults.With(w.proberResultsSuccessfulMetricLabels).Inc()
		ProberDuration.With(w.proberDurationSuccessfulMetricLabels).Observe(time.Since(startTime).Seconds())
	case results.Failure:
		ProberResults.With(w.proberResultsFailedMetricLabels).Inc()
	default:
		ProberResults.With(w.proberResultsUnknownMetricLabels).Inc()
		ProberDuration.With(w.proberDurationUnknownMetricLabels).Observe(time.Since(startTime).Seconds())
	}

	if w.lastResult == result {
		w.resultRun++
	} else {
		w.lastResult = result
		w.resultRun = 1
	}

	if (result == results.Failure && w.resultRun < int(w.spec.FailureThreshold)) ||
		(result == results.Success && w.resultRun < int(w.spec.SuccessThreshold)) {
		// Success or failure is below threshold - leave the probe state unchanged.保持探针状态不变
		return true
	}

	w.resultsManager.Set(w.containerID, result, w.pod)

	if (w.probeType == liveness || w.probeType == startup) && result == results.Failure {
		// The container fails a liveness/startup check, it will need to be restarted.
		// Stop probing until we see a new container ID. This is to reduce the
		// chance of hitting #21751, where running `docker exec` when a
		// container is being stopped may lead to corrupted container state.
		w.onHold = true
		w.resultRun = 0
	}

	return true
}

func deepCopyPrometheusLabels(m metrics.Labels) metrics.Labels {
	ret := make(metrics.Labels, len(m))
	for k, v := range m {
		ret[k] = v
	}
	return ret
}

func getPodLabelName(pod *v1.Pod) string {
	// 	vcluster-demo-6fd6585d4-bqdz7
	podName := pod.Name
	if pod.GenerateName != "" {
		podNameSlice := strings.Split(pod.Name, "-")
		podName = strings.Join(podNameSlice[:len(podNameSlice)-1], "-")             // 去掉随机字符串
		if label, ok := pod.GetLabels()[apps.DefaultDeploymentUniqueLabelKey]; ok { // pod-template-hash
			podName = strings.ReplaceAll(podName, fmt.Sprintf("-%s", label), "") // 去掉哈希值
		}
		// 	vcluster-demo
	}

	return podName
}
