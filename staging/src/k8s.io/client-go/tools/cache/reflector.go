/*
Copyright 2014 The Kubernetes Authors.

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
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"reflect"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/naming"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/pager"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
	"k8s.io/utils/trace"
)

const defaultExpectedTypeName = "<unspecified>"

type Reflector struct {
	name string // 名称,默认是file:line
	// 下面三个为了确认类型
	expectedTypeName string                   // watch 类型的名称
	expectedType     reflect.Type             // watch 类型
	expectedGVK      *schema.GroupVersionKind // watch gvk类型

	reflectorStore Store         // 存储,具体由 DeltaFIFO 实现存储
	listerWatcher  ListerWatcher // 用来从 api-server 拉取全量和增量资源
	// 下面两个用来做失败重试
	backoffManager         wait.BackoffManager // 管理回退ListWatch
	initConnBackoffManager wait.BackoffManager // 管理回退与ListAndWatch的Watch调用的初始连接.

	MaxInternalErrorRetryDuration time.Duration // 收到错误以后 ,最大的retry时间

	resyncPeriod                         time.Duration // informer 使用者重新同步的周期
	ShouldResync                         func() bool   // 是否应该同步 func (p *sharedProcessor) shouldResync() bool {
	clock                                clock.Clock   // 允许测试操作时间
	paginatedResult                      bool          // 定义list调用是否强制分页.它基于初始列表调用的结果进行设置.
	lastSyncResourceVersion              string        // 最后同步的资源版本号,以此为依据,watch 只会监听大于此值的资源
	isLastSyncResourceVersionUnavailable bool          // 最后同步的资源版本号是否可用
	// lastSyncResourceVersionMutex guards read/write access to lastSyncResourceVersion
	lastSyncResourceVersionMutex sync.RWMutex
	WatchListPageSize            int64 // watch 分页大小
	// Called whenever the ListAndWatch drops the connection with an error.
	watchErrorHandler WatchErrorHandler
}

// ResourceVersionUpdater is an interface that allows reflectorStore implementation to
// track the current resource version of the reflector. This is especially
// important if storage bookmarks are enabled.
type ResourceVersionUpdater interface {
	// UpdateResourceVersion is called each time current resource version of the reflector
	// is updated.
	UpdateResourceVersion(resourceVersion string)
}

// The WatchErrorHandler is called whenever ListAndWatch drops the
// connection with an error. After calling this handler, the informer
// will backoff and retry.
//
// The default implementation looks at the error type and tries to log
// the error message at an appropriate level.
//
// Implementations of this handler may display the error message in other
// ways. Implementations should return quickly - any expensive processing
// should be offloaded.
type WatchErrorHandler func(r *Reflector, err error)

// DefaultWatchErrorHandler is the default implementation of WatchErrorHandler
func DefaultWatchErrorHandler(r *Reflector, err error) {
	switch {
	case isExpiredError(err):
		// Don't set LastSyncResourceVersionUnavailable - LIST call with ResourceVersion=RV already
		// has a semantic that it returns data at least as fresh as provided RV.
		// So first try to LIST with setting RV to resource version of last observed object.
		klog.V(4).Infof("%s: watch of %v closed with: %v", r.name, r.expectedTypeName, err)
	case err == io.EOF:
		// watch closed normally
	case err == io.ErrUnexpectedEOF:
		klog.V(1).Infof("%s: Watch for %v closed with unexpected EOF: %v", r.name, r.expectedTypeName, err)
	default:
		utilruntime.HandleError(fmt.Errorf("%s: Failed to watch %v: %v", r.name, r.expectedTypeName, err))
	}
}

var (
	// We try to spread the load on apiserver by setting timeouts for
	// watch requests - it is random in [minWatchTimeout, 2*minWatchTimeout].
	minWatchTimeout = 5 * time.Minute
)

// NewReflector creates a new Reflector object which will keep the
// given reflectorStore up to date with the server's contents for the given
// resource. Reflector promises to only put things in the reflectorStore that
// have the type of expectedType, unless expectedType is nil. If
// resyncPeriod is non-zero, then the reflector will periodically
// consult its ShouldResync function to determine whether to invoke
// the Store's Resync operation; `ShouldResync==nil` means always
// "yes".  This enables you to use reflectors to periodically process
// everything as well as incrementally processing the things that
// change.
func NewReflector(lw ListerWatcher, expectedType interface{}, store Store, resyncPeriod time.Duration) *Reflector {
	return NewNamedReflector(naming.GetNameFromCallsite(internalPackages...), lw, expectedType, store, resyncPeriod) // ✅
}

// NewNamedReflector same as NewReflector, but with a specified name for logging
func NewNamedReflector(name string, lw ListerWatcher, expectedType interface{}, store Store, resyncPeriod time.Duration) *Reflector {
	realClock := &clock.RealClock{}
	r := &Reflector{
		name:           name,
		listerWatcher:  lw,
		reflectorStore: store, // ✅
		// 重试机制, 可以有效降低api server的负载,也就是重试间隔会越来越长
		backoffManager:         wait.NewExponentialBackoffManager(800*time.Millisecond, 30*time.Second, 2*time.Minute, 2.0, 1.0, realClock), // 定时器
		initConnBackoffManager: wait.NewExponentialBackoffManager(800*time.Millisecond, 30*time.Second, 2*time.Minute, 2.0, 1.0, realClock),
		resyncPeriod:           resyncPeriod,
		clock:                  realClock,
		watchErrorHandler:      WatchErrorHandler(DefaultWatchErrorHandler),
	}
	r.setExpectedType(expectedType)
	return r
}

func (r *Reflector) setExpectedType(expectedType interface{}) {
	r.expectedType = reflect.TypeOf(expectedType)
	if r.expectedType == nil {
		r.expectedTypeName = defaultExpectedTypeName
		return
	}

	r.expectedTypeName = r.expectedType.String()

	if obj, ok := expectedType.(*unstructured.Unstructured); ok {
		// Use gvk to check that watch event objects are of the desired type.
		gvk := obj.GroupVersionKind()
		if gvk.Empty() {
			klog.V(4).Infof("Reflector from %s configured with expectedType of *unstructured.Unstructured with empty GroupVersionKind.", r.name)
			return
		}
		r.expectedGVK = &gvk
		r.expectedTypeName = gvk.String()
	}
}

// internalPackages 是创建默认反射器名称时忽略的包.这些包在NewReflector的公共调用链中,因此它们是反射器的低熵名称
var internalPackages = []string{"client-go/tools/cache/"}

// Run 重复使用反射器的ListAndWatch来获取所有对象和后续增量.
// Run will exit when stopCh is closed.
func (r *Reflector) Run(stopCh <-chan struct{}) {
	klog.V(3).Infof("Starting reflector %s (%s) from %s", r.expectedTypeName, r.resyncPeriod, r.name)
	wait.BackoffUntil(func() {
		if err := r.ListAndWatch(stopCh); err != nil {
			r.watchErrorHandler(r, err)
		}
	}, r.backoffManager, true, stopCh)
	klog.V(3).Infof("Stopping reflector %s (%s) from %s", r.expectedTypeName, r.resyncPeriod, r.name)
}

var (
	// nothing will ever be sent down this channel
	neverExitWatch <-chan time.Time = make(chan time.Time)

	// Used to indicate that watching stopped because of a signal from the stop
	// channel passed in from a client of the reflector.
	errorStopRequested = errors.New("stop requested")
)

// resyncChan returns a channel which will receive something when a resync is
// required, and a cleanup function.
func (r *Reflector) resyncChan() (<-chan time.Time, func() bool) {
	if r.resyncPeriod == 0 {
		return neverExitWatch, func() bool { return false }
	}
	// The cleanup function is required: imagine the scenario where watches
	// always fail so we end up listing frequently. Then, if we don't
	// manually stop the timer, we could end up with many timers active
	// concurrently.
	t := r.clock.NewTimer(r.resyncPeriod)
	return t.C(), t.Stop
}

// ListAndWatch first lists all items and get the resource version at the moment of call,
// and then use the resource version to watch.
// It returns error if ListAndWatch didn't even try to initialize watch.
func (r *Reflector) ListAndWatch(stopCh <-chan struct{}) error {
	fmt.Println("ListAndWatch", time.Now().Unix())
	klog.V(3).Infof("Listing and watching %v from %s", r.expectedTypeName, r.name)

	err := r.list(stopCh)
	if err != nil {
		return err
	}

	resyncerrc := make(chan error, 1)
	cancelCh := make(chan struct{})
	defer close(cancelCh)
	go func() {
		resyncCh, cleanup := r.resyncChan() // 定时CHANNEL
		defer func() {
			cleanup() // Call the last one written into cleanup
		}()
		for {
			select {
			case <-resyncCh:
			case <-stopCh:
				return
			case <-cancelCh:
				return
			}
			if r.ShouldResync == nil || r.ShouldResync() {
				klog.V(4).Infof("%s: forcing resync", r.name)

				if err := r.reflectorStore.Resync(); err != nil { // 通过判断indexerCache 与本地数据, 将本地没有的数据同步过来 , 不知道为啥要这么干
					resyncerrc <- err
					return
				}
			}
			cleanup()
			resyncCh, cleanup = r.resyncChan()
		}
	}()

	retry := NewRetryWithDeadline(r.MaxInternalErrorRetryDuration, time.Minute, apierrors.IsInternalError, r.clock)
	for {
		fmt.Println("ListAndWatch for", time.Now().Unix())
		// give the stopCh a chance to stop the loop, even in case of continue statements further down on errors
		select {
		case <-stopCh:
			return nil
		default:
		}
		// 超时时间 是5~10分钟
		timeoutSeconds := int64(minWatchTimeout.Seconds() * (rand.Float64() + 1.0))
		options := metav1.ListOptions{
			ResourceVersion:     r.LastSyncResourceVersion(),
			TimeoutSeconds:      &timeoutSeconds, // 如果超时没有接收到任何Event,需要停止监听,避免一直阻塞
			AllowWatchBookmarks: true,            // 用于降低api server压力,bookmark类型响应的对象主要只有RV信息
		}

		// 在发送请求之前启动时钟,因为有些代理直到发送第一个监视事件之后才刷新标头
		start := r.clock.Now()
		// 开始监听
		w, err := r.listerWatcher.Watch(options)
		if err != nil {
			if utilnet.IsConnectionRefused(err) || apierrors.IsTooManyRequests(err) {
				<-r.initConnBackoffManager.Backoff().C()
				continue
			}
			return err
		}
		// 重要
		err = watchHandler(start, w, r.reflectorStore, r.expectedType, r.expectedGVK, r.name, r.expectedTypeName, r.setLastSyncResourceVersion, r.clock, resyncerrc, stopCh) // ✅
		retry.After(err)
		if err != nil {
			if err != errorStopRequested {
				switch {
				case isExpiredError(err):
					// Don't set LastSyncResourceVersionUnavailable - LIST call with ResourceVersion=RV already
					// has a semantic that it returns data at least as fresh as provided RV.
					// So first try to LIST with setting RV to resource version of last observed object.
					klog.V(4).Infof("%s: watch of %v closed with: %v", r.name, r.expectedTypeName, err)
				case apierrors.IsTooManyRequests(err):
					klog.V(2).Infof("%s: watch of %v returned 429 - backing off", r.name, r.expectedTypeName)
					<-r.initConnBackoffManager.Backoff().C()
					continue
				case apierrors.IsInternalError(err) && retry.ShouldRetry():
					klog.V(2).Infof("%s: retrying watch of %v internal error: %v", r.name, r.expectedTypeName, err)
					continue
				default:
					klog.Warningf("%s: watch of %v ended with: %v", r.name, r.expectedTypeName, err)
				}
			}
			return nil
		}
	}
}

// list simply lists all items and records a resource version obtained from the server at the moment of the call.
// the resource version can be used for further progress notification (aka. watch).
func (r *Reflector) list(stopCh <-chan struct{}) error {
	var resourceVersion string
	options := metav1.ListOptions{ResourceVersion: r.relistResourceVersion()} // ResourceVersion="" 会直接请求到etcd  "0"会访问cache

	initTrace := trace.New("Reflector ListAndWatch", trace.Field{Key: "name", Value: r.name})
	defer initTrace.LogIfLong(10 * time.Second) // 把超过10秒的步骤打印出来
	var list runtime.Object
	var paginatedResult bool
	var err error
	listCh := make(chan struct{}, 1)
	panicCh := make(chan interface{}, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				panicCh <- r
			}
		}()
		//开始尝试收集list的chunks,
		pager := pager.New(pager.SimplePageFunc(func(opts metav1.ListOptions) (runtime.Object, error) { // ✅
			// 	indexerCache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), "pods", "", fields.Everything())
			return r.listerWatcher.List(opts)
		}))
		switch {
		case r.WatchListPageSize != 0:
			pager.PageSize = r.WatchListPageSize
		case r.paginatedResult:
		case options.ResourceVersion != "" && options.ResourceVersion != "0":
			pager.PageSize = 0
		}

		list, paginatedResult, err = pager.List(context.Background(), options) // ✅
		if isExpiredError(err) || isTooLargeResourceVersionError(err) {
			r.setIsLastSyncResourceVersionUnavailable(true) // 下一次list会从etcd获取
			// Retry immediately if the resource version used to list is unavailable.
			// The pager already falls back to full list if paginated list calls fail due to an "Expired" error on
			// continuation pages, but the pager might not be enabled, the full list might fail because the
			// resource version it is listing at is expired or the indexerCache may not yet be synced to the provided
			// resource version. So we need to fallback to resourceVersion="" in all to recover and ensure
			// the reflector makes forward progress.
			list, paginatedResult, err = pager.List(context.Background(), metav1.ListOptions{ResourceVersion: r.relistResourceVersion()})
		}
		close(listCh)
	}()
	select {
	case <-stopCh:
		return nil
	case r := <-panicCh:
		panic(r)
	case <-listCh:
	}
	initTrace.Step("Objects listed", trace.Field{Key: "error", Value: err})
	if err != nil {
		klog.Warningf("%s: failed to list %v: %v", r.name, r.expectedTypeName, err)
		return fmt.Errorf("failed to list %v: %w", r.expectedTypeName, err)
	}

	// We check if the list was paginated and if so set the paginatedResult based on that.
	// However, we want to do that only for the initial list (which is the only case
	// when we set ResourceVersion="0"). The reasoning behind it is that later, in some
	// situations we may force listing directly from etcd (by setting ResourceVersion="")
	// which will return paginated result, even if watch indexerCache is enabled. However, in
	// that case, we still want to prefer sending requests to watch indexerCache if possible.
	//
	// Paginated result returned for request with ResourceVersion="0" mean that watch
	// indexerCache is disabled and there are a lot of objects of a given type. In such case,
	// there is no need to prefer listing from watch indexerCache.
	if options.ResourceVersion == "0" && paginatedResult {
		r.paginatedResult = true
	}

	r.setIsLastSyncResourceVersionUnavailable(false) // list 成功
	listMetaInterface, err := meta.ListAccessor(list)
	if err != nil {
		return fmt.Errorf("unable to understand list result %#v: %v", list, err)
	}
	resourceVersion = listMetaInterface.GetResourceVersion()
	initTrace.Step("Resource version extracted")
	items, err := meta.ExtractList(list) // 将list得到的items添加到 DeltaFifo 中,也就是添加一个SyncDeltaType,不过这里的resourceVersion没有实际用到
	if err != nil {
		return fmt.Errorf("unable to understand list result %#v (%v)", list, err)
	}
	initTrace.Step("Objects extracted")
	if err := r.syncWith(items, resourceVersion); err != nil { // 对应 2.Add Obj to fifo
		return fmt.Errorf("unable to sync list result: %v", err)
	}
	initTrace.Step("SyncWith done")
	r.setLastSyncResourceVersion(resourceVersion)
	initTrace.Step("Resource version updated")
	return nil
}

// syncWith replaces the reflectorStore's items with the given list.
func (r *Reflector) syncWith(items []runtime.Object, resourceVersion string) error {
	found := make([]interface{}, 0, len(items))
	for _, item := range items {
		found = append(found, item)
	}
	_ = new(DeltaFIFO).Replace
	return r.reflectorStore.Replace(found, resourceVersion) // ✅
}

// watchHandler 收到变更之后的触发函数
func watchHandler(start time.Time,
	w watch.Interface,
	reflectorStore Store,
	expectedType reflect.Type,
	expectedGVK *schema.GroupVersionKind,
	name string,
	expectedTypeName string,
	setLastSyncResourceVersion func(string),
	clock clock.Clock,
	errc chan error,
	stopCh <-chan struct{},
) error {
	eventCount := 0
	// 当前函数返回时需要关闭 watch.Interface 因为新一轮的调用会传递新的watch.Interface
	defer w.Stop()

loop:
	for {
		select {
		case <-stopCh:
			return errorStopRequested
		case err := <-errc:
			return err
		case event, ok := <-w.ResultChan():
			if !ok {
				break loop
			}
			if event.Type == watch.Error {
				return apierrors.FromObject(event.Object)
			}
			// 类型不匹配
			if expectedType != nil {
				if e, a := expectedType, reflect.TypeOf(event.Object); e != a {
					utilruntime.HandleError(fmt.Errorf("%s: expected type %v, but watch event object had type %v", name, e, a))
					continue
				}
			}
			// 没有对应go语言结构体的对象可以通过这种方式来指定期望类型
			if expectedGVK != nil {
				if e, a := *expectedGVK, event.Object.GetObjectKind().GroupVersionKind(); e != a {
					utilruntime.HandleError(fmt.Errorf("%s: expected gvk %v, but watch event object had gvk %v", name, e, a))
					continue
				}
			}
			meta, err := meta.Accessor(event.Object)
			if err != nil {
				utilruntime.HandleError(fmt.Errorf("%s: unable to understand watch event %#v", name, event))
				continue
			}
			// 新的resourceVersion
			resourceVersion := meta.GetResourceVersion()
			//_ = reflectorStore.(*DeltaFIFO).Add 				// 对应 2.Add Obj to fifo
			//_ = reflectorStore.(*cacher.watchCache).Update 	// 对应 2.Add Obj to fifo
			//_ = reflectorStore.(*DeltaFIFO).Delete 			// 对应 2.Add Obj to fifo
			switch event.Type {
			case watch.Added:
				err := reflectorStore.Add(event.Object)
				if err != nil {
					utilruntime.HandleError(fmt.Errorf("%s: unable to add watch event object (%#v) to reflectorStore: %v", name, event.Object, err))
				}
			case watch.Modified:
				err := reflectorStore.Update(event.Object)
				if err != nil {
					utilruntime.HandleError(fmt.Errorf("%s: unable to update watch event object (%#v) to reflectorStore: %v", name, event.Object, err))
				}
			case watch.Deleted:
				// TODO: Will any consumers need access to the "last known
				// state", which is passed in event.Object? If so, may need
				// to change this.
				err := reflectorStore.Delete(event.Object)
				if err != nil {
					utilruntime.HandleError(fmt.Errorf("%s: unable to delete watch event object (%#v) from reflectorStore: %v", name, event.Object, err))
				}
			case watch.Bookmark:
				// A `Bookmark` 意味着watch 已经在这里同步,只需更新resourceVersion
			default:
				utilruntime.HandleError(fmt.Errorf("%s: unable to understand watch event %#v", name, event))
			}
			setLastSyncResourceVersion(resourceVersion)
			if rvu, ok := reflectorStore.(ResourceVersionUpdater); ok {
				rvu.UpdateResourceVersion(resourceVersion)
			}
			eventCount++
		}
	}

	watchDuration := clock.Since(start)                   // 耗时
	if watchDuration < 1*time.Second && eventCount == 0 { // 1秒就结束了,且没有收到事件、属于异常情况
		return fmt.Errorf("very short watch: %s: Unexpected watch close - watch lasted less than a second and no items received", name)
	}
	klog.V(4).Infof("%s: Watch close - %v total %v items received", name, expectedTypeName, eventCount)
	return nil
}

// LastSyncResourceVersion is the resource version observed when last sync with the underlying reflectorStore
// The value returned is not synchronized with access to the underlying reflectorStore and is not thread-safe
func (r *Reflector) LastSyncResourceVersion() string {
	r.lastSyncResourceVersionMutex.RLock()
	defer r.lastSyncResourceVersionMutex.RUnlock()
	return r.lastSyncResourceVersion
}

func (r *Reflector) setLastSyncResourceVersion(v string) {
	r.lastSyncResourceVersionMutex.Lock()
	defer r.lastSyncResourceVersionMutex.Unlock()
	r.lastSyncResourceVersion = v
}

// relistResourceVersion determines the resource version the reflector should list or relist from.
// Returns either the lastSyncResourceVersion so that this reflector will relist with a resource
// versions no older than has already been observed in relist results or watch events, or, if the last relist resulted
// in an HTTP 410 (Gone) status code, returns "" so that the relist will use the latest resource version available in
// etcd via a quorum read.
func (r *Reflector) relistResourceVersion() string {
	r.lastSyncResourceVersionMutex.RLock()
	defer r.lastSyncResourceVersionMutex.RUnlock()

	if r.isLastSyncResourceVersionUnavailable {
		// Since this reflector makes paginated list requests, and all paginated list requests skip the watch indexerCache
		// if the lastSyncResourceVersion is unavailable, we set ResourceVersion="" and list again to re-establish reflector
		// to the latest available ResourceVersion, using a consistent read from etcd.
		return ""
	}
	if r.lastSyncResourceVersion == "" {
		// For performance reasons, initial list performed by reflector uses "0" as resource version to allow it to
		// be served from the watch indexerCache if it is enabled.
		return "0"
	}
	return r.lastSyncResourceVersion
}

// setIsLastSyncResourceVersionUnavailable sets if the last list or watch request with lastSyncResourceVersion returned
// "expired" or "too large resource version" error.
func (r *Reflector) setIsLastSyncResourceVersionUnavailable(isUnavailable bool) {
	r.lastSyncResourceVersionMutex.Lock()
	defer r.lastSyncResourceVersionMutex.Unlock()
	r.isLastSyncResourceVersionUnavailable = isUnavailable
}

func isExpiredError(err error) bool {
	// In Kubernetes 1.17 and earlier, the api server returns both apierrors.StatusReasonExpired and
	// apierrors.StatusReasonGone for HTTP 410 (Gone) status code responses. In 1.18 the kube server is more consistent
	// and always returns apierrors.StatusReasonExpired. For backward compatibility we can only remove the apierrors.IsGone
	// check when we fully drop support for Kubernetes 1.17 servers from reflectors.
	return apierrors.IsResourceExpired(err) || apierrors.IsGone(err)
}

func isTooLargeResourceVersionError(err error) bool {
	if apierrors.HasStatusCause(err, metav1.CauseTypeResourceVersionTooLarge) {
		return true
	}
	// In Kubernetes 1.17.0-1.18.5, the api server doesn't set the error status cause to
	// metav1.CauseTypeResourceVersionTooLarge to indicate that the requested minimum resource
	// version is larger than the largest currently available resource version. To ensure backward
	// compatibility with these server versions we also need to detect the error based on the content
	// of the error message field.
	if !apierrors.IsTimeout(err) {
		return false
	}
	apierr, ok := err.(apierrors.APIStatus)
	if !ok || apierr == nil || apierr.Status().Details == nil {
		return false
	}
	for _, cause := range apierr.Status().Details.Causes {
		// Matches the message returned by api server 1.17.0-1.18.5 for this error condition
		if cause.Message == "Too large resource version" {
			return true
		}
	}
	return false
}
