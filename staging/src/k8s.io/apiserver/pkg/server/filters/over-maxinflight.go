/*
Copyright 2016 The Kubernetes Authors.

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

package filters

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/metrics"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	fcmetrics "k8s.io/apiserver/pkg/util/flowcontrol/metrics"

	"k8s.io/klog/v2"
)

const (
	// 速率限制上重试间隔的常数。
	// TODO: maybe make this dynamic? or user-adjustable?
	retryAfter = "1"
	// 多久更新一次 flight 使用率指标。因为指标在一段时间内跟踪最大值，使其更长将增加指标值。
	inflightUsageMetricUpdatePeriod = time.Second
)

var (
	nonMutatingRequestVerbs = sets.NewString("get", "list", "watch")
	watchVerbs              = sets.NewString("watch")
)

func handleError(w http.ResponseWriter, r *http.Request, err error) {
	errorMsg := fmt.Sprintf("Internal Server Error: %#v", r.RequestURI)
	http.Error(w, errorMsg, http.StatusInternalServerError)
	klog.Errorf(err.Error())
}

// requestWatermark 用于跟踪在处理特定阶段的最大请求数。
type requestWatermark struct {
	phase               string
	nonMutatingObserver fcmetrics.RatioedGauge
	mutatingObserver    fcmetrics.RatioedGauge // 记录当前值
	lock                sync.Mutex
	readOnlyWatermark   int
	mutatingWatermark   int
}

func (w *requestWatermark) recordMutating(mutatingVal int) {
	w.mutatingObserver.Set(float64(mutatingVal))

	w.lock.Lock()
	defer w.lock.Unlock()

	if w.mutatingWatermark < mutatingVal {
		w.mutatingWatermark = mutatingVal
	}
}

func (w *requestWatermark) recordReadOnly(readOnlyVal int) {
	w.nonMutatingObserver.Set(float64(readOnlyVal))

	w.lock.Lock()
	defer w.lock.Unlock()

	if w.readOnlyWatermark < readOnlyVal {
		w.readOnlyWatermark = readOnlyVal
	}
}

// watermark tracks requests being executed (not waiting in a queue)
var watermark = &requestWatermark{
	phase: metrics.ExecutingPhase,
}

// startWatermarkMaintenance starts the goroutines to observe and maintain the specified watermark.
func startWatermarkMaintenance(watermark *requestWatermark, stopCh <-chan struct{}) {
	// Periodically update the inflight usage metric.
	go wait.Until(func() {
		watermark.lock.Lock()
		readOnlyWatermark := watermark.readOnlyWatermark
		mutatingWatermark := watermark.mutatingWatermark
		watermark.readOnlyWatermark = 0
		watermark.mutatingWatermark = 0
		watermark.lock.Unlock()

		metrics.UpdateInflightRequestMetrics(watermark.phase, readOnlyWatermark, mutatingWatermark)
	}, inflightUsageMetricUpdatePeriod, stopCh)
}

var initMaxInFlightOnce sync.Once

func initMaxInFlight(nonMutatingLimit, mutatingLimit int) {
	initMaxInFlightOnce.Do(func() {
		// 获取这些计量器的延迟直到它们的基础指标已注册，以便它们附着于有效的实现。
		watermark.nonMutatingObserver = fcmetrics.GetExecutingReadonlyConcurrency()
		watermark.mutatingObserver = fcmetrics.GetExecutingMutatingConcurrency()
		if nonMutatingLimit != 0 {
			watermark.nonMutatingObserver.SetDenominator(float64(nonMutatingLimit))
			klog.V(2).InfoS("Set denominator for readonly requests", "limit", nonMutatingLimit)
		}
		if mutatingLimit != 0 {
			watermark.mutatingObserver.SetDenominator(float64(mutatingLimit))
			klog.V(2).InfoS("Set denominator for mutating requests", "limit", mutatingLimit)
		}
	})
}

// WithMaxInFlightLimit limits the number of in-flight requests to buffer size of the passed in channel.
func WithMaxInFlightLimit(
	handler http.Handler,
	nonMutatingLimit int,
	mutatingLimit int,
	longRunningRequestCheck apirequest.LongRunningRequestCheck,
) http.Handler {
	if nonMutatingLimit == 0 && mutatingLimit == 0 {
		return handler
	}
	var nonMutatingChan chan bool
	var mutatingChan chan bool
	if nonMutatingLimit != 0 {
		nonMutatingChan = make(chan bool, nonMutatingLimit)
		klog.V(2).InfoS("Initialized nonMutatingChan", "len", nonMutatingLimit)
	} else {
		klog.V(2).InfoS("Running with nil nonMutatingChan")
	}
	if mutatingLimit != 0 {
		mutatingChan = make(chan bool, mutatingLimit)
		klog.V(2).InfoS("Initialized mutatingChan", "len", mutatingLimit)
	} else {
		klog.V(2).InfoS("Running with nil mutatingChan")
	}
	initMaxInFlight(nonMutatingLimit, mutatingLimit)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		requestInfo, ok := apirequest.RequestInfoFrom(ctx)
		if !ok {
			handleError(w, r, fmt.Errorf("no RequestInfo found in context, handler chain must be wrong"))
			return
		}

		// Skip tracking long running events.
		if longRunningRequestCheck != nil && longRunningRequestCheck(r, requestInfo) {
			handler.ServeHTTP(w, r)
			return
		}

		var c chan bool
		isMutatingRequest := !nonMutatingRequestVerbs.Has(requestInfo.Verb)
		if isMutatingRequest {
			c = mutatingChan
		} else {
			c = nonMutatingChan
		}

		if c == nil {
			handler.ServeHTTP(w, r)
		} else {

			select {
			case c <- true:
				// 我们注意到在请求正在被服务和请求完成被服务后的并发级别，因为这两个状态都对并发采样统计产生贡献。
				if isMutatingRequest {
					watermark.recordMutating(len(c))
				} else {
					watermark.recordReadOnly(len(c))
				}
				defer func() {
					<-c
					if isMutatingRequest {
						watermark.recordMutating(len(c))
					} else {
						watermark.recordReadOnly(len(c))
					}
				}()
				handler.ServeHTTP(w, r)

			default:
				// at this point we're about to return a 429, BUT not all actors should be rate limited.  A system:master is so powerful
				// that they should always get an answer.  It's a super-admin or a loopback connection.
				if currUser, ok := apirequest.UserFrom(ctx); ok {
					for _, group := range currUser.GetGroups() {
						//default代表队列已满，但是如果请求的group中含有 system:masters，则放行 - 因为apiserver认为这个组是很重要的请求，不能被限流
						if group == user.SystemPrivilegedGroup { // 特权组，不过滤
							handler.ServeHTTP(w, r)
							return
						}
					}
				}
				//直接返回错误

				// We need to split this data between buckets used for throttling.
				metrics.RecordDroppedRequest(r, requestInfo, metrics.APIServerComponent, isMutatingRequest)
				metrics.RecordRequestTermination(r, requestInfo, metrics.APIServerComponent, http.StatusTooManyRequests)
				tooManyRequests(r, w)
			}
		}
	})
}

// StartMaxInFlightWatermarkMaintenance starts the goroutines to observe and maintain watermarks for max-in-flight
// requests.
func StartMaxInFlightWatermarkMaintenance(stopCh <-chan struct{}) {
	startWatermarkMaintenance(watermark, stopCh)
}

func tooManyRequests(req *http.Request, w http.ResponseWriter) {
	// Return a 429 status indicating "Too Many Requests"
	w.Header().Set("Retry-After", retryAfter)
	http.Error(w, "Too many requests, please try again later.", http.StatusTooManyRequests)
}
