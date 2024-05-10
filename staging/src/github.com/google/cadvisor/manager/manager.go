// Copyright 2014 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Manager of cAdvisor-monitored containers.
package manager

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/cadvisor/accelerators"
	"github.com/google/cadvisor/cache/memory"
	"github.com/google/cadvisor/collector"
	"github.com/google/cadvisor/container"
	"github.com/google/cadvisor/container/raw"
	"github.com/google/cadvisor/events"
	"github.com/google/cadvisor/fs"
	info "github.com/google/cadvisor/info/v1"
	v2 "github.com/google/cadvisor/info/v2"
	"github.com/google/cadvisor/machine"
	"github.com/google/cadvisor/nvm"
	"github.com/google/cadvisor/perf"
	"github.com/google/cadvisor/resctrl"
	"github.com/google/cadvisor/stats"
	"github.com/google/cadvisor/utils/oomparser"
	"github.com/google/cadvisor/utils/sysfs"
	"github.com/google/cadvisor/version"
	"github.com/google/cadvisor/watcher"

	"github.com/opencontainers/runc/libcontainer/cgroups"

	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
)

var globalHousekeepingInterval = flag.Duration("global_housekeeping_interval", 1*time.Minute, "Interval between global housekeepings")
var updateMachineInfoInterval = flag.Duration("update_machine_info_interval", 5*time.Minute, "机器信息更新的间隔.")
var logCadvisorUsage = flag.Bool("log_cadvisor_usage", false, "是否记录cAdvisor容器的使用日志")
var eventStorageAgeLimit = flag.String("event_storage_age_limit", "default=24h", "存储事件的最大时间长度(每种类型).Value是一个以逗号分隔的键值列表,其中键是事件类型(例如:creation, oom)或“default”,Value是持续时间.Default应用于所有非指定的事件类型")
var eventStorageEventLimit = flag.String("event_storage_event_limit", "default=100000", "要存储的最大事件数(每种类型).Value是一个以逗号分隔的键值列表,其中键是事件类型(例如:creation, oom)或“default”,Value是一个整数.Default应用于所有非指定的事件类型")
var applicationMetricsCountLimit = flag.Int("application_metrics_count_limit", 100, "要存储的最大应用程序度量数(每个容器)")

// The namespace under which Docker aliases are unique.
const DockerNamespace = "docker"

var HousekeepingConfigFlags = HouskeepingConfig{
	flag.Duration("max_housekeeping_interval", 60*time.Second, "Largest interval to allow between container housekeepings"),
	flag.Bool("allow_dynamic_housekeeping", true, "Whether to allow the housekeeping interval to be dynamic"),
}

// The Manager interface defines operations for starting a manager and getting
// container and machine information.
type Manager interface {
	// Start the manager. Calling other manager methods before this returns
	// may produce undefined behavior.
	Start() error

	Stop() error

	// GetContainerInfo 获取容器信息
	GetContainerInfo(containerName string, query *info.ContainerInfoRequest) (*info.ContainerInfo, error)

	// GetContainerInfoV2 获取容器的V2版本信息.递归(子容器)请求是尽最大努力的,在部分失败的情况下,可能会返回部分结果和错误.
	GetContainerInfoV2(containerName string, options v2.RequestOptions) (map[string]v2.ContainerInfo, error)

	// Get information about all subcontainers of the specified container (includes self).
	SubcontainersInfo(containerName string, query *info.ContainerInfoRequest) ([]*info.ContainerInfo, error)

	// Gets all the Docker containers. Return is a map from full container name to ContainerInfo.
	AllDockerContainers(query *info.ContainerInfoRequest) (map[string]info.ContainerInfo, error)

	// Gets information about a specific Docker container. The specified name is within the Docker namespace.
	DockerContainer(dockerName string, query *info.ContainerInfoRequest) (info.ContainerInfo, error)

	// Gets spec for all containers based on request options.
	GetContainerSpec(containerName string, options v2.RequestOptions) (map[string]v2.ContainerSpec, error)

	// Gets summary stats for all containers based on request options.
	GetDerivedStats(containerName string, options v2.RequestOptions) (map[string]v2.DerivedStats, error)

	// Get info for all requested containers based on the request options.
	GetRequestedContainersInfo(containerName string, options v2.RequestOptions) (map[string]*info.ContainerInfo, error)

	// Returns true if the named container exists.
	Exists(containerName string) bool

	GetMachineInfo() (*info.MachineInfo, error)

	// Get version information about different components we depend on.
	GetVersionInfo() (*info.VersionInfo, error)

	// GetFsInfoByFsUUID returns the information of the device having the
	// specified filesystem uuid. If no such device with the UUID exists, this
	// function will return the fs.ErrNoSuchDevice error.
	GetFsInfoByFsUUID(uuid string) (v2.FsInfo, error)

	GetDirFsInfo(dir string) (v2.FsInfo, error) // 获取包含给定目录的文件系统的文件系统信息.

	// Get filesystem information for a given label.
	// Returns information for all global filesystems if label is empty.
	GetFsInfo(label string) ([]v2.FsInfo, error)

	// Get ps output for a container.
	GetProcessList(containerName string, options v2.RequestOptions) ([]v2.ProcessInfo, error)

	// Get events streamed through passedChannel that fit the request.
	WatchForEvents(request *events.Request) (*events.EventChannel, error)

	// Get past events that have been detected and that fit the request.
	GetPastEvents(request *events.Request) ([]*info.Event, error)

	CloseEventChannel(watchID int)

	// Returns debugging information. Map of lines per category.
	DebugInfo() map[string][]string
}

// Housekeeping configuration for the manager
type HouskeepingConfig = struct {
	Interval     *time.Duration
	AllowDynamic *bool
}

// New takes a memory storage and returns a new manager.
func New(
	memoryCache *memory.InMemoryCache,
	sysfs sysfs.SysFs,
	houskeepingConfig HouskeepingConfig,
	includedMetricsSet container.MetricSet,
	collectorHTTPClient *http.Client,
	rawContainerCgroupPathPrefixWhiteList,
	containerEnvMetadataWhiteList []string,
	perfEventsFile string,
	resctrlInterval time.Duration,
) (Manager, error) {
	if memoryCache == nil {
		return nil, fmt.Errorf("manager requires memory storage")
	}

	// 检测我们正在运行的容器.
	selfContainer := "/"
	var err error
	// 避免在cgroup v2上使用GetOwnCgroupPath,因为它不受libcontainer支持.
	//
	//cgroup是Linux内核中的一个特性,用于限制和隔离进程的资源使用.cgroup有两个版本,即cgroup v1和cgroup v2.在cgroup v1中,
	//每个进程都有自己的cgroup路径,可以使用GetOwnCgroupPath函数来获取它的路径.但是,在cgroup v2中,每个进程的cgroup路径是动态生成的,无法使用GetOwnCgroupPath函数来获取它的路径.
	//
	//因此,如果在cgroup v2上使用GetOwnCgroupPath函数,可能会导致错误或不可预测的结果.为了避免这种情况,建议在cgroup v2上使用其他函数或工具来获取进程的cgroup路径,或者使用cgroup v1来进行进程隔离.
	if !cgroups.IsCgroup2UnifiedMode() { // 不是 v2 unified 模式
		selfContainer, err = cgroups.GetOwnCgroup("cpu")
		if err != nil {
			return nil, err
		}
		klog.V(2).Infof("cAdvisor running in container: %q", selfContainer)
	}
	// 根据挂载点信息获取fsinfo对象
	context := fs.Context{}
	if err := container.InitializeFSContext(&context); err != nil {
		return nil, err
	}

	fsInfo, err := fs.NewFsInfo(context) // ✅
	if err != nil {
		return nil, err
	}

	// 如果使用主机的rootfs启动了cAdvisor,则假定它在自己的命名空间中运行.
	inHostNamespace := false
	_, err = os.Stat("/rootfs/proc")
	if os.IsNotExist(err) {
		//rootfs是Linux系统中的一个特殊文件系统,它包含了系统启动时必需的文件和目录.在Docker等容器平台中,rootfs通常被用于构建容器镜像.如果在主机上挂载了rootfs,并使用它来启动cAdvisor,则可以假定cAdvisor在自己的命名空间中运行,这意味着它无法直接访问主机上的其他进程或资源.
		//
		//在这种情况下,cAdvisor需要使用一些特殊的技巧来获取系统信息和指标.例如,它可以使用procfs文件系统来获取主机上的进程信息,或者使用cgroup文件系统来获取容器的资源使用情况.此外,cAdvisor还可以使用一些Linux内核特性,例如UTS命名空间和网络命名空间,来隔离自身并获取更多的系统信息.
		//
		//需要注意的是,使用rootfs启动cAdvisor可能会带来一些安全风险和性能问题,因此建议在必要时才使用这种方式启动cAdvisor,并采取必要的安全措施和优化措施.
		inHostNamespace = true
	}

	// Register for new subcontainers.
	eventsChannel := make(chan watcher.ContainerEvent, 16)

	newManager := &manager{
		containers:                            make(map[namespacedContainerName]*containerData),
		quitChannels:                          make([]chan error, 0, 2),
		memoryCache:                           memoryCache,
		fsInfo:                                fsInfo,
		sysFs:                                 sysfs,
		cadvisorContainer:                     selfContainer, // /
		inHostNamespace:                       inHostNamespace,
		startupTime:                           time.Now(),
		maxHousekeepingInterval:               *houskeepingConfig.Interval,
		allowDynamicHousekeeping:              *houskeepingConfig.AllowDynamic,
		includedMetrics:                       includedMetricsSet,
		containerWatchers:                     []watcher.ContainerWatcher{},
		eventsChannel:                         eventsChannel,
		collectorHTTPClient:                   collectorHTTPClient,
		nvidiaManager:                         accelerators.NewNvidiaManager(includedMetricsSet),
		rawContainerCgroupPathPrefixWhiteList: rawContainerCgroupPathPrefixWhiteList,
		containerEnvMetadataWhiteList:         containerEnvMetadataWhiteList,
	}
	// 获取machineInfo,包含节点的机器信息
	machineInfo, err := machine.Info(sysfs, fsInfo, inHostNamespace)
	if err != nil {
		return nil, err
	}
	newManager.machineInfo = *machineInfo
	klog.V(1).Infof("Machine: %+v", newManager.machineInfo)

	newManager.perfManager, err = perf.NewManager(perfEventsFile, machineInfo.Topology)
	if err != nil {
		return nil, err
	}

	newManager.resctrlManager, err = resctrl.NewManager(resctrlInterval, resctrl.Setup, machineInfo.CPUVendorID, inHostNamespace)
	if err != nil {
		klog.V(4).Infof("Cannot gather resctrl metrics: %v", err)
	}

	versionInfo, err := getVersionInfo()
	if err != nil {
		return nil, err
	}
	klog.V(1).Infof("Version: %+v", *versionInfo)

	newManager.eventHandler = events.NewEventManager(parseEventsStoragePolicy())
	return newManager, nil
}

// A namespaced container name.
type namespacedContainerName struct {
	// The namespace of the container. Can be empty for the root namespace.
	Namespace string

	// The name of the container in this namespace.
	Name string
}

type manager struct {
	containers                            map[namespacedContainerName]*containerData // 当前受到监控的容器存在一个map中 containerData结构中包括了对容器的各种具体操作方式和相关信息
	containersLock                        sync.RWMutex                               // 对map中数据存取时采用的Lock
	memoryCache                           *memory.InMemoryCache
	fsInfo                                fs.FsInfo
	sysFs                                 sysfs.SysFs
	machineMu                             sync.RWMutex // protects machineInfo
	machineInfo                           info.MachineInfo
	quitChannels                          []chan error
	cadvisorContainer                     string              // cadvisor容器的名称  /
	inHostNamespace                       bool                //
	eventHandler                          events.EventManager //
	startupTime                           time.Time
	maxHousekeepingInterval               time.Duration
	allowDynamicHousekeeping              bool
	includedMetrics                       container.MetricSet
	containerWatchers                     []watcher.ContainerWatcher
	eventsChannel                         chan watcher.ContainerEvent
	collectorHTTPClient                   *http.Client
	nvidiaManager                         stats.Manager
	perfManager                           stats.Manager
	resctrlManager                        resctrl.Manager
	rawContainerCgroupPathPrefixWhiteList []string // 这是一个原始容器的 cgroup 路径前缀白名单列表.  为nil
	// List of container env prefix whitelist, the matched container envs would be collected into metrics as extra labels.
	containerEnvMetadataWhiteList []string
}

// Start the container manager. 一次性的
func (m *manager) Start() error {
	m.containerWatchers = container.InitializePlugins(m, m.fsInfo, m.includedMetrics)

	err := raw.Register(m, m.fsInfo, m.includedMetrics, m.rawContainerCgroupPathPrefixWhiteList) // ✅
	if err != nil {
		klog.Errorf("Registration of the raw container factory failed: %v", err)
	}

	rawWatcher, err := raw.NewRawContainerWatcher() // ✅
	if err != nil {
		return err
	}
	m.containerWatchers = append(m.containerWatchers, rawWatcher) // ✅

	// 启动对oom的监听
	err = m.watchForNewOoms() // ✅
	if err != nil {
		klog.Warningf("Could not configure a source for OOM detection, disabling OOM events: %v", err)
	}

	// 如果没有容器工厂,则不要启动任何清理工作,并提供我们已有的信息.
	if !container.HasFactories() {
		return nil
	}

	// Create root and then recover all containers.
	err = m.createContainer("/", watcher.Raw)
	if err != nil {
		return err
	}
	klog.V(2).Infof("Starting recovery of all containers")
	err = m.detectSubcontainers("/") // 检测子容器, 检测要添加或删除的所有容器
	if err != nil {
		return err
	}
	klog.V(2).Infof("Recovery completed")

	// Watch for new container.
	quitWatcher := make(chan error)
	// 启动对新容器的监听,添加相关的资源采集
	err = m.watchForNewContainers(quitWatcher)
	if err != nil {
		return err
	}
	m.quitChannels = append(m.quitChannels, quitWatcher)

	// Look for new containers in the main housekeeping thread.
	quitGlobalHousekeeping := make(chan error)
	m.quitChannels = append(m.quitChannels, quitGlobalHousekeeping)
	go m.globalHousekeeping(quitGlobalHousekeeping) // 添加、删除容器

	quitUpdateMachineInfo := make(chan error)
	m.quitChannels = append(m.quitChannels, quitUpdateMachineInfo)
	go m.updateMachineInfo(quitUpdateMachineInfo)

	return nil
}

func (m *manager) Stop() error {
	defer m.nvidiaManager.Destroy()
	defer m.destroyCollectors()
	// Stop and wait on all quit channels.
	for i, c := range m.quitChannels {
		// Send the exit signal and wait on the thread to exit (by closing the channel).
		c <- nil
		err := <-c
		if err != nil {
			// Remove the channels that quit successfully.
			m.quitChannels = m.quitChannels[i:]
			return err
		}
	}
	m.quitChannels = make([]chan error, 0, 2)
	nvm.Finalize()
	perf.Finalize()
	return nil
}

func (m *manager) destroyCollectors() {
	for _, container := range m.containers {
		container.perfCollector.Destroy()
		container.resctrlCollector.Destroy()
	}
}

// 定时更新机器信息给kubelet等使用
func (m *manager) updateMachineInfo(quit chan error) {
	ticker := time.NewTicker(*updateMachineInfoInterval)
	for {
		select {
		case <-ticker.C:
			info, err := machine.Info(m.sysFs, m.fsInfo, m.inHostNamespace)
			if err != nil {
				klog.Errorf("Could not get machine info: %v", err)
				break
			}
			m.machineMu.Lock()
			m.machineInfo = *info
			m.machineMu.Unlock()
			klog.V(5).Infof("Update machine info: %+v", *info)
		case <-quit:
			ticker.Stop()
			quit <- nil
			return
		}
	}
}

// 垃圾清理
func (m *manager) globalHousekeeping(quit chan error) {
	// Long housekeeping is either 100ms or half of the housekeeping interval.
	longHousekeeping := 100 * time.Millisecond
	if *globalHousekeepingInterval/2 < longHousekeeping {
		longHousekeeping = *globalHousekeepingInterval / 2
	}

	ticker := time.NewTicker(*globalHousekeepingInterval)
	for {
		select {
		case t := <-ticker.C:
			start := time.Now()

			// Check for new containers.
			err := m.detectSubcontainers("/")
			if err != nil {
				klog.Errorf("Failed to detect containers: %s", err)
			}

			// Log if housekeeping took too long.
			duration := time.Since(start)
			if duration >= longHousekeeping {
				klog.V(3).Infof("Global Housekeeping(%d) took %s", t.Unix(), duration)
			}
		case <-quit:
			// Quit if asked to do so.
			quit <- nil
			klog.Infof("Exiting global housekeeping thread")
			return
		}
	}
}

func (m *manager) getContainerData(containerName string) (*containerData, error) {
	var cont *containerData
	var ok bool
	func() {
		m.containersLock.RLock()
		defer m.containersLock.RUnlock()

		// Ensure we have the container.
		cont, ok = m.containers[namespacedContainerName{
			Name: containerName,
		}]
	}()
	if !ok {
		return nil, fmt.Errorf("unknown container %q", containerName)
	}
	return cont, nil
}

func (m *manager) GetDerivedStats(containerName string, options v2.RequestOptions) (map[string]v2.DerivedStats, error) {
	conts, err := m.getRequestedContainers(containerName, options)
	if err != nil {
		return nil, err
	}
	var errs partialFailure
	stats := make(map[string]v2.DerivedStats)
	for name, cont := range conts {
		d, err := cont.DerivedStats()
		if err != nil {
			errs.append(name, "DerivedStats", err)
		}
		stats[name] = d
	}
	return stats, errs.OrNil()
}

func (m *manager) GetContainerSpec(containerName string, options v2.RequestOptions) (map[string]v2.ContainerSpec, error) {
	conts, err := m.getRequestedContainers(containerName, options)
	if err != nil {
		return nil, err
	}
	var errs partialFailure
	specs := make(map[string]v2.ContainerSpec)
	for name, cont := range conts {
		cinfo, err := cont.GetInfo(false)
		if err != nil {
			errs.append(name, "GetInfo", err)
		}
		spec := m.getV2Spec(cinfo)
		specs[name] = spec
	}
	return specs, errs.OrNil()
}

// Get V2 container spec from v1 container info.
func (m *manager) getV2Spec(cinfo *containerInfo) v2.ContainerSpec {
	spec := m.getAdjustedSpec(cinfo)
	return v2.ContainerSpecFromV1(&spec, cinfo.Aliases, cinfo.Namespace)
}

func (m *manager) getAdjustedSpec(cinfo *containerInfo) info.ContainerSpec {
	spec := cinfo.Spec

	// Set default value to an actual value
	if spec.HasMemory {
		// Memory.Limit is 0 means there's no limit
		if spec.Memory.Limit == 0 {
			m.machineMu.RLock()
			spec.Memory.Limit = uint64(m.machineInfo.MemoryCapacity)
			m.machineMu.RUnlock()
		}
	}
	return spec
}

func (m *manager) GetContainerInfo(containerName string, query *info.ContainerInfoRequest) (*info.ContainerInfo, error) {
	cont, err := m.getContainerData(containerName)
	if err != nil {
		return nil, err
	}
	return m.containerDataToContainerInfo(cont, query)
}

func (m *manager) GetContainerInfoV2(containerName string, options v2.RequestOptions) (map[string]v2.ContainerInfo, error) {
	containers, err := m.getRequestedContainers(containerName, options)
	if err != nil {
		return nil, err
	}

	var errs partialFailure
	var nilTime time.Time // Ignored.

	infos := make(map[string]v2.ContainerInfo, len(containers))
	for name, container := range containers {
		result := v2.ContainerInfo{}
		cinfo, err := container.GetInfo(false)
		if err != nil {
			errs.append(name, "GetInfo", err)
			infos[name] = result
			continue
		}
		result.Spec = m.getV2Spec(cinfo)

		stats, err := m.memoryCache.RecentStats(name, nilTime, nilTime, options.Count)
		if err != nil {
			errs.append(name, "RecentStats", err)
			infos[name] = result
			continue
		}

		result.Stats = v2.ContainerStatsFromV1(containerName, &cinfo.Spec, stats)
		infos[name] = result
	}

	return infos, errs.OrNil()
}

func (m *manager) containerDataToContainerInfo(cont *containerData, query *info.ContainerInfoRequest) (*info.ContainerInfo, error) {
	// Get the info from the container.
	cinfo, err := cont.GetInfo(true)
	if err != nil {
		return nil, err
	}

	stats, err := m.memoryCache.RecentStats(cinfo.Name, query.Start, query.End, query.NumStats)
	if err != nil {
		return nil, err
	}

	// Make a copy of the info for the user.
	ret := &info.ContainerInfo{
		ContainerReference: cinfo.ContainerReference,
		Subcontainers:      cinfo.Subcontainers,
		Spec:               m.getAdjustedSpec(cinfo),
		Stats:              stats,
	}
	return ret, nil
}

func (m *manager) getContainer(containerName string) (*containerData, error) {
	m.containersLock.RLock()
	defer m.containersLock.RUnlock()
	cont, ok := m.containers[namespacedContainerName{Name: containerName}]
	if !ok {
		return nil, fmt.Errorf("unknown container %q", containerName)
	}
	return cont, nil
}

func (m *manager) getSubcontainers(containerName string) map[string]*containerData {
	m.containersLock.RLock()
	defer m.containersLock.RUnlock()
	containersMap := make(map[string]*containerData, len(m.containers))

	// Get all the unique subcontainers of the specified container
	matchedName := path.Join(containerName, "/")
	for i := range m.containers {
		if m.containers[i] == nil {
			continue
		}
		name := m.containers[i].info.Name
		if name == containerName || strings.HasPrefix(name, matchedName) {
			containersMap[m.containers[i].info.Name] = m.containers[i]
		}
	}
	return containersMap
}

func (m *manager) SubcontainersInfo(containerName string, query *info.ContainerInfoRequest) ([]*info.ContainerInfo, error) {
	containersMap := m.getSubcontainers(containerName)

	containers := make([]*containerData, 0, len(containersMap))
	for _, cont := range containersMap {
		containers = append(containers, cont)
	}
	return m.containerDataSliceToContainerInfoSlice(containers, query)
}

func (m *manager) getAllDockerContainers() map[string]*containerData {
	m.containersLock.RLock()
	defer m.containersLock.RUnlock()
	containers := make(map[string]*containerData, len(m.containers))

	// Get containers in the Docker namespace.
	for name, cont := range m.containers {
		if name.Namespace == DockerNamespace {
			containers[cont.info.Name] = cont
		}
	}
	return containers
}

func (m *manager) AllDockerContainers(query *info.ContainerInfoRequest) (map[string]info.ContainerInfo, error) {
	containers := m.getAllDockerContainers()

	output := make(map[string]info.ContainerInfo, len(containers))
	for name, cont := range containers {
		inf, err := m.containerDataToContainerInfo(cont, query)
		if err != nil {
			// Ignore the error because of race condition and return best-effort result.
			if err == memory.ErrDataNotFound {
				klog.Warningf("Error getting data for container %s because of race condition", name)
				continue
			}
			return nil, err
		}
		output[name] = *inf
	}
	return output, nil
}

func (m *manager) getDockerContainer(containerName string) (*containerData, error) {
	m.containersLock.RLock()
	defer m.containersLock.RUnlock()

	// Check for the container in the Docker container namespace.
	cont, ok := m.containers[namespacedContainerName{
		Namespace: DockerNamespace,
		Name:      containerName,
	}]

	// Look for container by short prefix name if no exact match found.
	if !ok {
		for contName, c := range m.containers {
			if contName.Namespace == DockerNamespace && strings.HasPrefix(contName.Name, containerName) {
				if cont == nil {
					cont = c
				} else {
					return nil, fmt.Errorf("unable to find container. Container %q is not unique", containerName)
				}
			}
		}

		if cont == nil {
			return nil, fmt.Errorf("unable to find Docker container %q", containerName)
		}
	}

	return cont, nil
}

func (m *manager) DockerContainer(containerName string, query *info.ContainerInfoRequest) (info.ContainerInfo, error) {
	container, err := m.getDockerContainer(containerName)
	if err != nil {
		return info.ContainerInfo{}, err
	}

	inf, err := m.containerDataToContainerInfo(container, query)
	if err != nil {
		return info.ContainerInfo{}, err
	}
	return *inf, nil
}

func (m *manager) containerDataSliceToContainerInfoSlice(containers []*containerData, query *info.ContainerInfoRequest) ([]*info.ContainerInfo, error) {
	if len(containers) == 0 {
		return nil, fmt.Errorf("no containers found")
	}

	// Get the info for each container.
	output := make([]*info.ContainerInfo, 0, len(containers))
	for i := range containers {
		cinfo, err := m.containerDataToContainerInfo(containers[i], query)
		if err != nil {
			// Skip containers with errors, we try to degrade gracefully.
			klog.V(4).Infof("convert container data to container info failed with error %s", err.Error())
			continue
		}
		output = append(output, cinfo)
	}

	return output, nil
}

func (m *manager) GetRequestedContainersInfo(containerName string, options v2.RequestOptions) (map[string]*info.ContainerInfo, error) {
	containers, err := m.getRequestedContainers(containerName, options)
	if err != nil {
		return nil, err
	}
	var errs partialFailure
	containersMap := make(map[string]*info.ContainerInfo)
	query := info.ContainerInfoRequest{
		NumStats: options.Count,
	}
	for name, data := range containers {
		info, err := m.containerDataToContainerInfo(data, &query)
		if err != nil {
			if err == memory.ErrDataNotFound {
				klog.Warningf("Error getting data for container %s because of race condition", name)
				continue
			}
			errs.append(name, "containerDataToContainerInfo", err)
		}
		containersMap[name] = info
	}
	return containersMap, errs.OrNil()
}

func (m *manager) getRequestedContainers(containerName string, options v2.RequestOptions) (map[string]*containerData, error) {
	containersMap := make(map[string]*containerData)
	switch options.IdType {
	case v2.TypeName:
		if !options.Recursive {
			cont, err := m.getContainer(containerName)
			if err != nil {
				return containersMap, err
			}
			containersMap[cont.info.Name] = cont
		} else {
			containersMap = m.getSubcontainers(containerName)
			if len(containersMap) == 0 {
				return containersMap, fmt.Errorf("unknown container: %q", containerName)
			}
		}
	case v2.TypeDocker:
		if !options.Recursive {
			containerName = strings.TrimPrefix(containerName, "/")
			cont, err := m.getDockerContainer(containerName)
			if err != nil {
				return containersMap, err
			}
			containersMap[cont.info.Name] = cont
		} else {
			if containerName != "/" {
				return containersMap, fmt.Errorf("invalid request for docker container %q with subcontainers", containerName)
			}
			containersMap = m.getAllDockerContainers()
		}
	default:
		return containersMap, fmt.Errorf("invalid request type %q", options.IdType)
	}
	if options.MaxAge != nil {
		// update stats for all containers in containersMap
		var waitGroup sync.WaitGroup
		waitGroup.Add(len(containersMap))
		for _, container := range containersMap {
			go func(cont *containerData) {
				cont.OnDemandHousekeeping(*options.MaxAge)
				waitGroup.Done()
			}(container)
		}
		waitGroup.Wait()
	}
	return containersMap, nil
}

func (m *manager) GetDirFsInfo(dir string) (v2.FsInfo, error) {
	device, err := m.fsInfo.GetDirFsDevice(dir) // ✅
	if err != nil {
		return v2.FsInfo{}, fmt.Errorf("failed to get device for dir %q: %v", dir, err)
	}
	return m.getFsInfoByDeviceName(device.Device)
}

func (m *manager) GetFsInfoByFsUUID(uuid string) (v2.FsInfo, error) {
	device, err := m.fsInfo.GetDeviceInfoByFsUUID(uuid)
	if err != nil {
		return v2.FsInfo{}, err
	}
	return m.getFsInfoByDeviceName(device.Device)
}

// GetFsInfo 获取文件系统挂载点的使用量
func (m *manager) GetFsInfo(label string) ([]v2.FsInfo, error) { // ✅
	var empty time.Time
	// Get latest data from filesystems hanging off root container.
	stats, err := m.memoryCache.RecentStats("/", empty, empty, 1)
	if err != nil {
		return nil, err
	}
	dev := ""
	if len(label) != 0 {
		dev, err = m.fsInfo.GetDeviceForLabel(label)
		if err != nil {
			return nil, err
		}
	}
	fsInfo := []v2.FsInfo{}
	for i := range stats[0].Filesystem {
		fs := stats[0].Filesystem[i]
		if len(label) != 0 && fs.Device != dev {
			continue
		}
		mountpoint, err := m.fsInfo.GetMountpointForDevice(fs.Device)
		if err != nil {
			return nil, err
		}
		labels, err := m.fsInfo.GetLabelsForDevice(fs.Device)
		if err != nil {
			return nil, err
		}

		fi := v2.FsInfo{
			Timestamp:  stats[0].Timestamp,
			Device:     fs.Device,
			Mountpoint: mountpoint,
			Capacity:   fs.Limit,
			Usage:      fs.Usage,
			Available:  fs.Available,
			Labels:     labels,
		}
		if fs.HasInodes {
			fi.Inodes = &fs.Inodes
			fi.InodesFree = &fs.InodesFree
		}
		fsInfo = append(fsInfo, fi)
	}
	return fsInfo, nil
}

func (m *manager) GetMachineInfo() (*info.MachineInfo, error) {
	m.machineMu.RLock()
	defer m.machineMu.RUnlock()
	return m.machineInfo.Clone(), nil
}

func (m *manager) GetVersionInfo() (*info.VersionInfo, error) {
	// TODO: Consider caching this and periodically updating.  The VersionInfo may change if
	// the docker daemon is started after the cAdvisor client is created.  Caching the value
	// would be helpful so we would be able to return the last known docker version if
	// docker was down at the time of a query.
	return getVersionInfo()
}

func (m *manager) Exists(containerName string) bool {
	m.containersLock.RLock()
	defer m.containersLock.RUnlock()

	namespacedName := namespacedContainerName{
		Name: containerName,
	}

	_, ok := m.containers[namespacedName]
	return ok
}

func (m *manager) GetProcessList(containerName string, options v2.RequestOptions) ([]v2.ProcessInfo, error) {
	// override recursive. Only support single container listing.
	options.Recursive = false
	// override MaxAge.  ProcessList does not require updated stats.
	options.MaxAge = nil
	conts, err := m.getRequestedContainers(containerName, options)
	if err != nil {
		return nil, err
	}
	if len(conts) != 1 {
		return nil, fmt.Errorf("Expected the request to match only one container")
	}
	// TODO(rjnagal): handle count? Only if we can do count by type (eg. top 5 cpu users)
	ps := []v2.ProcessInfo{}
	for _, cont := range conts {
		ps, err = cont.GetProcessList(m.cadvisorContainer, m.inHostNamespace)
		if err != nil {
			return nil, err
		}
	}
	return ps, nil
}

// 注册指标收集器
func (m *manager) registerCollectors(collectorConfigs map[string]string, cont *containerData) error {
	for k, v := range collectorConfigs {
		configFile, err := cont.ReadFile(v, m.inHostNamespace)
		if err != nil {
			return fmt.Errorf("failed to read config file %q for config %q, container %q: %v", k, v, cont.info.Name, err)
		}
		klog.V(4).Infof("Got config from %q: %q", v, configFile)

		if strings.HasPrefix(k, "prometheus") || strings.HasPrefix(k, "Prometheus") {
			newCollector, err := collector.NewPrometheusCollector(k, configFile, *applicationMetricsCountLimit, cont.handler, m.collectorHTTPClient)
			if err != nil {
				return fmt.Errorf("failed to create collector for container %q, config %q: %v", cont.info.Name, k, err)
			}
			err = cont.collectorManager.RegisterCollector(newCollector)
			if err != nil {
				return fmt.Errorf("failed to register collector for container %q, config %q: %v", cont.info.Name, k, err)
			}
		} else {
			newCollector, err := collector.NewCollector(k, configFile, *applicationMetricsCountLimit, cont.handler, m.collectorHTTPClient)
			if err != nil {
				return fmt.Errorf("failed to create collector for container %q, config %q: %v", cont.info.Name, k, err)
			}
			err = cont.collectorManager.RegisterCollector(newCollector)
			if err != nil {
				return fmt.Errorf("failed to register collector for container %q, config %q: %v", cont.info.Name, k, err)
			}
		}
	}
	return nil
}

// Watches for new containers started in the system. Runs forever unless there is a setup error.
func (m *manager) watchForNewContainers(quit chan error) error {
	// - 处理由watcher生产者通过eventsChannel发来的ContainerEvent事件
	//  - 如果是ContainerAdd就调用createContainer新增资源采集
	//  - 如果是ContainerDelete就调用destroyContainer删除资源采集
	//- createContainer内部逻辑较为复杂就不在这里展开了
	watched := make([]watcher.ContainerWatcher, 0)
	for _, watcher := range m.containerWatchers {
		err := watcher.Start(m.eventsChannel)
		if err != nil {
			for _, w := range watched {
				stopErr := w.Stop()
				if stopErr != nil {
					klog.Warningf("Failed to stop wacher %v with error: %v", w, stopErr)
				}
			}
			return err
		}
		watched = append(watched, watcher)
	}

	// There is a race between starting the watch and new container creation so we do a detection before we read new containers.
	err := m.detectSubcontainers("/")
	if err != nil {
		return err
	}

	// Listen to events from the container handler.
	go func() {
		for {
			select {
			case event := <-m.eventsChannel:
				switch {
				case event.EventType == watcher.ContainerAdd:
					switch event.WatchSource {
					default:
						err = m.createContainer(event.Name, event.WatchSource)
					}
				case event.EventType == watcher.ContainerDelete:
					err = m.destroyContainer(event.Name)
				}
				if err != nil {
					klog.Warningf("Failed to process watch event %+v: %v", event, err)
				}
			case <-quit:
				var errs partialFailure

				// Stop processing events if asked to quit.
				for i, watcher := range m.containerWatchers {
					err := watcher.Stop()
					if err != nil {
						errs.append(fmt.Sprintf("watcher %d", i), "Stop", err)
					}
				}

				if len(errs) > 0 {
					quit <- errs
				} else {
					quit <- nil
					klog.Infof("Exiting thread watching subcontainers")
					return
				}
			}
		}
	}()
	return nil
}

func (m *manager) watchForNewOoms() error {
	//- watchForNewOoms中首先新建kmsg log 解析器 ,解析/dev/kmsg中的内核日志
	//- 同时新建outStream chan 用作生产者和消费者之间的交互
	klog.V(2).Infof("Started watching for new ooms in manager")
	outStream := make(chan *oomparser.OomInstance, 10)
	oomLog, err := oomparser.New()
	if err != nil {
		return err
	}
	// 启动生成者,就是从内核日志解析容器oom的日志,
	//
	//- 过程就是判断有没有invoked oom-killer:字段
	//- 然后再用containerRegexp正则判断是容器进程的oom
	go oomLog.StreamOoms(outStream) // 开始解析/dev/kmsg里的日志

	go func() {
		// 启动消费者产生oom 和oomKill event
		for oomInstance := range outStream {
			// Surface OOM and OOM kill events.
			newEvent := &info.Event{
				ContainerName: oomInstance.ContainerName,
				Timestamp:     oomInstance.TimeOfDeath,
				EventType:     info.EventOom,
			}
			err := m.eventHandler.AddEvent(newEvent) // EventOom
			if err != nil {
				klog.Errorf("failed to add OOM event for %q: %v", oomInstance.ContainerName, err)
			}
			klog.V(3).Infof("Created an OOM event in container %q at %v", oomInstance.ContainerName, oomInstance.TimeOfDeath)

			newEvent = &info.Event{
				ContainerName: oomInstance.VictimContainerName,
				Timestamp:     oomInstance.TimeOfDeath,
				EventType:     info.EventOomKill,
				EventData: info.EventData{
					OomKill: &info.OomKillEventData{
						Pid:         oomInstance.Pid,
						ProcessName: oomInstance.ProcessName,
					},
				},
			}
			err = m.eventHandler.AddEvent(newEvent) // EventOomKill
			if err != nil {
				klog.Errorf("failed to add OOM kill event for %q: %v", oomInstance.ContainerName, err)
			}

			// Count OOM events for later collection by prometheus
			request := v2.RequestOptions{
				IdType: v2.TypeName,
				Count:  1,
			}
			conts, err := m.getRequestedContainers(oomInstance.ContainerName, request)
			if err != nil {
				klog.V(2).Infof("failed getting container info for %q: %v", oomInstance.ContainerName, err)
				continue
			}
			if len(conts) != 1 {
				klog.V(2).Info("Expected the request to match only one container")
				continue
			}
			for _, cont := range conts {
				atomic.AddUint64(&cont.oomEvents, 1)
			}
		}
	}()
	return nil
}

// can be called by the api which will take events returned on the channel
func (m *manager) WatchForEvents(request *events.Request) (*events.EventChannel, error) {
	return m.eventHandler.WatchEvents(request)
}

// can be called by the api which will return all events satisfying the request
func (m *manager) GetPastEvents(request *events.Request) ([]*info.Event, error) {
	return m.eventHandler.GetEvents(request)
}

// called by the api when a client is no longer listening to the channel
func (m *manager) CloseEventChannel(watchID int) {
	m.eventHandler.StopWatch(watchID)
}

// Parses the events StoragePolicy from the flags.
func parseEventsStoragePolicy() events.StoragePolicy {
	policy := events.DefaultStoragePolicy()
	var _ = policy.DefaultMaxNumEvents
	// Parse max age.
	parts := strings.Split(*eventStorageAgeLimit, ",")
	for _, part := range parts {
		items := strings.Split(part, "=")
		if len(items) != 2 {
			klog.Warningf("Unknown event storage policy %q when parsing max age", part)
			continue
		}
		dur, err := time.ParseDuration(items[1])
		if err != nil {
			klog.Warningf("Unable to parse event max age duration %q: %v", items[1], err)
			continue
		}
		if items[0] == "default" {
			policy.DefaultMaxAge = dur
			continue
		}
		policy.PerTypeMaxAge[info.EventType(items[0])] = dur
	}

	// Parse max number.
	parts = strings.Split(*eventStorageEventLimit, ",")
	for _, part := range parts {
		items := strings.Split(part, "=")
		if len(items) != 2 {
			klog.Warningf("Unknown event storage policy %q when parsing max event limit", part)
			continue
		}
		val, err := strconv.Atoi(items[1])
		if err != nil {
			klog.Warningf("Unable to parse integer from %q: %v", items[1], err)
			continue
		}
		if items[0] == "default" {
			policy.DefaultMaxNumEvents = val
			continue
		}
		policy.PerTypeMaxNumEvents[info.EventType(items[0])] = val
	}

	return policy
}

func (m *manager) DebugInfo() map[string][]string {
	debugInfo := container.DebugInfo()

	// Get unique containers.
	var conts map[*containerData]struct{}
	func() {
		m.containersLock.RLock()
		defer m.containersLock.RUnlock()

		conts = make(map[*containerData]struct{}, len(m.containers))
		for _, c := range m.containers {
			conts[c] = struct{}{}
		}
	}()

	// List containers.
	lines := make([]string, 0, len(conts))
	for cont := range conts {
		lines = append(lines, cont.info.Name)
		if cont.info.Namespace != "" {
			lines = append(lines, fmt.Sprintf("\tNamespace: %s", cont.info.Namespace))
		}

		if len(cont.info.Aliases) != 0 {
			lines = append(lines, "\tAliases:")
			for _, alias := range cont.info.Aliases {
				lines = append(lines, fmt.Sprintf("\t\t%s", alias))
			}
		}
	}

	debugInfo["Managed containers"] = lines
	return debugInfo
}

func (m *manager) getFsInfoByDeviceName(deviceName string) (v2.FsInfo, error) { // ✅
	mountPoint, err := m.fsInfo.GetMountpointForDevice(deviceName)
	if err != nil {
		return v2.FsInfo{}, fmt.Errorf("failed to get mount point for device %q: %v", deviceName, err)
	}
	infos, err := m.GetFsInfo("")
	if err != nil {
		return v2.FsInfo{}, err
	}
	for _, info := range infos {
		if info.Mountpoint == mountPoint {
			return info, nil
		}
	}
	return v2.FsInfo{}, fmt.Errorf("cannot find filesystem info for device %q", deviceName)
}

// Create a container.
func (m *manager) createContainer(containerName string, watchSource watcher.ContainerWatchSource) error { // ✅
	m.containersLock.Lock()
	defer m.containersLock.Unlock()

	return m.createContainerLocked(containerName, watchSource) // ✅
}

func (m *manager) createContainerLocked(containerName string, watchSource watcher.ContainerWatchSource) error { // ✅
	namespacedName := namespacedContainerName{
		Name: containerName,
	}

	// Check that the container didn't already exist.
	if _, ok := m.containers[namespacedName]; ok {
		return nil
	}

	handler, accept, err := container.NewContainerHandler(containerName, watchSource, m.containerEnvMetadataWhiteList, m.inHostNamespace)
	if err != nil {
		return err
	}
	if !accept {
		// ignoring this container.
		klog.V(4).Infof("ignoring container %q", containerName)
		return nil
	}
	collectorManager, err := collector.NewCollectorManager()
	if err != nil {
		return err
	}

	logUsage := *logCadvisorUsage && containerName == m.cadvisorContainer
	cont, err := newContainerData(
		containerName,
		m.memoryCache,
		handler,
		logUsage,
		collectorManager,
		m.maxHousekeepingInterval,
		m.allowDynamicHousekeeping,
		clock.RealClock{},
	)
	if err != nil {
		return err
	}

	if !cgroups.IsCgroup2UnifiedMode() {
		devicesCgroupPath, err := handler.GetCgroupPath("devices")
		if err != nil {
			klog.Warningf("Error getting devices cgroup path: %v", err)
		} else {
			cont.nvidiaCollector, err = m.nvidiaManager.GetCollector(devicesCgroupPath)
			if err != nil {
				klog.V(4).Infof("GPU metrics may be unavailable/incomplete for container %s: %s", cont.info.Name, err)
			}
		}
	}
	if m.includedMetrics.Has(container.PerfMetrics) { // cadvisormetrics.MetricSet
		perfCgroupPath, err := handler.GetCgroupPath("perf_event")
		if err != nil {
			klog.Warningf("Error getting perf_event cgroup path: %q", err)
		} else {
			cont.perfCollector, err = m.perfManager.GetCollector(perfCgroupPath)
			if err != nil {
				klog.Errorf("Perf event metrics will not be available for container %q: %v", containerName, err)
			}
		}
	}

	if m.includedMetrics.Has(container.ResctrlMetrics) { // cadvisormetrics.MetricSet
		cont.resctrlCollector, err = m.resctrlManager.GetCollector(containerName, func() ([]string, error) {
			return cont.getContainerPids(m.inHostNamespace)
		}, len(m.machineInfo.Topology))
		if err != nil {
			klog.V(4).Infof("resctrl metrics will not be available for container %s: %s", cont.info.Name, err)
		}
	}

	// Add collectors
	labels := handler.GetContainerLabels() // 处理器的标签
	collectorConfigs := collector.GetCollectorConfigs(labels)
	err = m.registerCollectors(collectorConfigs, cont) // 注册指标收集器
	if err != nil {
		klog.Warningf("Failed to register collectors for %q: %v", containerName, err)
	}

	// Add the container name and all its aliases. The aliases must be within the namespace of the factory.
	m.containers[namespacedName] = cont
	for _, alias := range cont.info.Aliases {
		m.containers[namespacedContainerName{
			Namespace: cont.info.Namespace,
			Name:      alias,
		}] = cont
	}

	klog.V(3).Infof("Added container: %q (aliases: %v, namespace: %q)", containerName, cont.info.Aliases, cont.info.Namespace)

	contSpec, err := cont.handler.GetSpec()
	if err != nil {
		return err
	}

	contRef, err := cont.handler.ContainerReference()
	if err != nil {
		return err
	}

	newEvent := &info.Event{
		ContainerName: contRef.Name,
		Timestamp:     contSpec.CreationTime,
		EventType:     info.EventContainerCreation,
	}
	err = m.eventHandler.AddEvent(newEvent) // DefaultMaxNumEvents 该值默认是0,因此不会记录事件
	if err != nil {
		return err
	}
	// Start the container's housekeeping.
	return cont.Start() // ✅
}

func (m *manager) destroyContainer(containerName string) error { // ✅
	m.containersLock.Lock()
	defer m.containersLock.Unlock()

	return m.destroyContainerLocked(containerName) // ✅
}

func (m *manager) destroyContainerLocked(containerName string) error { // ✅
	namespacedName := namespacedContainerName{
		Name: containerName,
	}
	cont, ok := m.containers[namespacedName]
	if !ok {
		// Already destroyed, done.
		return nil
	}

	// Tell the container to stop.
	err := cont.Stop()
	if err != nil {
		return err
	}

	// Remove the container from our records (and all its aliases).
	delete(m.containers, namespacedName)
	for _, alias := range cont.info.Aliases {
		delete(m.containers, namespacedContainerName{
			Namespace: cont.info.Namespace,
			Name:      alias,
		})
	}
	klog.V(3).Infof("Destroyed container: %q (aliases: %v, namespace: %q)", containerName, cont.info.Aliases, cont.info.Namespace)

	contRef, err := cont.handler.ContainerReference()
	if err != nil {
		return err
	}

	newEvent := &info.Event{
		ContainerName: contRef.Name,
		Timestamp:     time.Now(),
		EventType:     info.EventContainerDeletion,
	}
	err = m.eventHandler.AddEvent(newEvent)
	if err != nil {
		return err
	}
	return nil
}

// 检测在指定时间中添加或删除的所有容器
func (m *manager) getContainersDiff(containerName string) (added []info.ContainerReference, removed []info.ContainerReference, err error) {
	// Get all subcontainers recursively.
	m.containersLock.RLock()
	cont, ok := m.containers[namespacedContainerName{
		Name: containerName,
	}]
	m.containersLock.RUnlock()
	if !ok {
		return nil, nil, fmt.Errorf("failed to find container %q while checking for new containers", containerName)
	}
	allContainers, err := cont.handler.ListContainers(container.ListRecursive) // 列表递归 cgroup 获取文件

	if err != nil {
		return nil, nil, err
	}
	allContainers = append(allContainers, info.ContainerReference{Name: containerName})

	m.containersLock.RLock()
	defer m.containersLock.RUnlock()

	// 确定哪些被添加,哪些被删除.
	allContainersSet := make(map[string]*containerData)
	for name, d := range m.containers { // 一致维护最新的数据,包括还没有生效的容器
		// 只添加规范名称.
		if d.info.Name == name.Name {
			allContainersSet[name.Name] = d
		}
	}

	// 某个时间段内新增加的容器
	for _, c := range allContainers {
		delete(allContainersSet, c.Name)
		_, ok := m.containers[namespacedContainerName{
			Name: c.Name,
		}]
		if !ok {
			added = append(added, c)
		}
	}

	// 某个时间段内删除的容器
	for _, d := range allContainersSet {
		removed = append(removed, d.info.ContainerReference)
	}

	return
}

// 检测子容器,并在代码中反映这些子容器的设置
func (m *manager) detectSubcontainers(containerName string) error {
	added, removed, err := m.getContainersDiff(containerName) // 检测在指定时间中添加或删除的所有容器
	if err != nil {
		return err
	}

	// Add the new containers.
	for _, cont := range added {
		err = m.createContainer(cont.Name, watcher.Raw)
		if err != nil {
			klog.Errorf("Failed to create existing container: %s: %s", cont.Name, err)
		}
	}

	// Remove the old containers.
	for _, cont := range removed {
		err = m.destroyContainer(cont.Name)
		if err != nil {
			klog.Errorf("Failed to destroy existing container: %s: %s", cont.Name, err)
		}
	}

	return nil
}

func getVersionInfo() (*info.VersionInfo, error) {

	kernelVersion := machine.KernelVersion()
	osVersion := machine.ContainerOsVersion()

	return &info.VersionInfo{
		KernelVersion:      kernelVersion,
		ContainerOsVersion: osVersion,
		CadvisorVersion:    version.Info["version"],
		CadvisorRevision:   version.Info["revision"],
	}, nil
}

// Helper for accumulating partial failures.
type partialFailure []string

func (f *partialFailure) append(id, operation string, err error) {
	*f = append(*f, fmt.Sprintf("[%q: %s: %s]", id, operation, err))
}

func (f partialFailure) Error() string {
	return fmt.Sprintf("partial failures: %s", strings.Join(f, ", "))
}

func (f partialFailure) OrNil() error {
	if len(f) == 0 {
		return nil
	}
	return f
}
