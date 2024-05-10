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

package cache

import (
	"sync"

	compbasemetrics "k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
)

var (
	// TODO: add plugin name + access mode labels to all these metrics
	seLinuxContainerContextErrors = compbasemetrics.NewGauge(
		&compbasemetrics.GaugeOpts{
			Name:           "volume_manager_selinux_container_errors_total",
			Help:           "Number of errors when kubelet cannot compute SELinux context for a container. Kubelet can't start such a Pod then and it will retry, therefore value of this metric may not represent the actual nr. of containers.",
			StabilityLevel: compbasemetrics.ALPHA,
		})
	seLinuxContainerContextWarnings = compbasemetrics.NewGauge(
		&compbasemetrics.GaugeOpts{
			Name:           "volume_manager_selinux_container_warnings_total",
			StabilityLevel: compbasemetrics.ALPHA,
			Help:           "Number of errors when kubelet cannot compute SELinux context for a container that are ignored. They will become real errors when SELinuxMountReadWriteOncePod feature is expanded to all volume access modes.",
		})
	seLinuxPodContextMismatchErrors = compbasemetrics.NewGauge(
		&compbasemetrics.GaugeOpts{
			Name:           "volume_manager_selinux_pod_context_mismatch_errors_total",
			Help:           "Number of errors when a Pod defines different SELinux contexts for its containers that use the same volume. Kubelet can't start such a Pod then and it will retry, therefore value of this metric may not represent the actual nr. of Pods.",
			StabilityLevel: compbasemetrics.ALPHA,
		})
	seLinuxPodContextMismatchWarnings = compbasemetrics.NewGauge(
		&compbasemetrics.GaugeOpts{
			Name:           "volume_manager_selinux_pod_context_mismatch_warnings_total",
			Help:           "Number of errors when a Pod defines different SELinux contexts for its containers that use the same volume. They are not errors yet, but they will become real errors when SELinuxMountReadWriteOncePod feature is expanded to all volume access modes.",
			StabilityLevel: compbasemetrics.ALPHA,
		})
	seLinuxVolumeContextMismatchErrors = compbasemetrics.NewGauge(
		&compbasemetrics.GaugeOpts{
			Name:           "volume_manager_selinux_volume_context_mismatch_errors_total",
			Help:           "Number of errors when a Pod uses a volume that is already mounted with a different SELinux context than the Pod needs. Kubelet can't start such a Pod then and it will retry, therefore value of this metric may not represent the actual nr. of Pods.",
			StabilityLevel: compbasemetrics.ALPHA,
		})
	seLinuxVolumeContextMismatchWarnings = compbasemetrics.NewGauge(
		&compbasemetrics.GaugeOpts{
			Name:           "volume_manager_selinux_volume_context_mismatch_warnings_total",
			Help:           "当一个 Pod 使用一个已经挂载了与 Pod 需要的不同 SELinux 上下文的卷时,会发生的错误数量.",
			StabilityLevel: compbasemetrics.ALPHA,
		})
	seLinuxVolumesAdmitted = compbasemetrics.NewGauge(
		&compbasemetrics.GaugeOpts{
			Name:           "volume_manager_selinux_volumes_admitted_total",
			Help:           "SELinux 上下文正确的卷的数量,并将使用 mount -o context 选项挂载.",
			StabilityLevel: compbasemetrics.ALPHA,
		})

	registerMetrics sync.Once
)

func registerSELinuxMetrics() {
	registerMetrics.Do(func() {
		legacyregistry.MustRegister(seLinuxContainerContextErrors)
		legacyregistry.MustRegister(seLinuxContainerContextWarnings)
		legacyregistry.MustRegister(seLinuxPodContextMismatchErrors)
		legacyregistry.MustRegister(seLinuxPodContextMismatchWarnings)
		legacyregistry.MustRegister(seLinuxVolumeContextMismatchErrors)
		legacyregistry.MustRegister(seLinuxVolumeContextMismatchWarnings)
		legacyregistry.MustRegister(seLinuxVolumesAdmitted)
	})
}
