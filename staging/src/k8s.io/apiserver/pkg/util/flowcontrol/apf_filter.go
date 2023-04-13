/*
Copyright 2019 The Kubernetes Authors.

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

package flowcontrol

import (
	"context"
	"strconv"
	"time"

	"k8s.io/apiserver/pkg/server/httplog"
	"k8s.io/apiserver/pkg/server/mux"
	fq "k8s.io/apiserver/pkg/util/flowcontrol/fairqueuing"
	"k8s.io/apiserver/pkg/util/flowcontrol/fairqueuing/eventclock"
	fqs "k8s.io/apiserver/pkg/util/flowcontrol/fairqueuing/queueset"
	"k8s.io/apiserver/pkg/util/flowcontrol/metrics"
	fcrequest "k8s.io/apiserver/pkg/util/flowcontrol/request"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"

	flowcontrol "k8s.io/api/flowcontrol/v1beta3"
	flowcontrolclient "k8s.io/client-go/kubernetes/typed/flowcontrol/v1beta3"
)

// ConfigConsumerAsFieldManager is how the config consuminng
// controller appears in an ObjectMeta ManagedFieldsEntry.Manager
const ConfigConsumerAsFieldManager = "api-priority-and-fairness-config-consumer-v1"

// Interface 定义API优先级和公平性过滤器如何与底层系统交互。
type Interface interface {
	// Handle takes care of queuing and dispatching a request
	// characterized by the given digest.  The given `noteFn` will be
	// invoked with the results of request classification.
	// The given `workEstimator` is called, if at all, after noteFn.
	// `workEstimator` will be invoked only when the request
	//  is classified as non 'exempt'.
	// 'workEstimator', when invoked, must return the
	// work parameters for the request.
	// If the request is queued then `queueNoteFn` will be called twice,
	// first with `true` and then with `false`; otherwise
	// `queueNoteFn` will not be called at all.  If Handle decides
	// that the request should be executed then `execute()` will be
	// invoked once to execute the request; otherwise `execute()` will
	// not be invoked.
	// Handle() should never return while execute() is running, even if
	// ctx is cancelled or times out.
	Handle(ctx context.Context,
		requestDigest RequestDigest,
		noteFn func(fs *flowcontrol.FlowSchema, pl *flowcontrol.PriorityLevelConfiguration, flowDistinguisher string),
		workEstimator func() fcrequest.WorkEstimate,
		queueNoteFn fq.QueueNoteFn,
		execFn func(),
	)

	// Run monitors config objects from the main apiservers and causes
	// any needed changes to local behavior.  This method ceases
	// activity and returns after the given channel is closed.
	Run(stopCh <-chan struct{}) error

	// Install installs debugging endpoints to the web-server.
	Install(c *mux.PathRecorderMux)

	// WatchTracker provides the WatchTracker interface.
	WatchTracker
}

// This request filter implements https://github.com/kubernetes/enhancements/blob/master/keps/sig-api-machinery/1040-priority-and-fairness/README.md

// New 创建一个新实例来实现API优先级和公平性
func New(
	informerFactory kubeinformers.SharedInformerFactory,
	flowcontrolClient flowcontrolclient.FlowcontrolV1beta3Interface,
	serverConcurrencyLimit int,
	requestWaitLimit time.Duration,
) Interface { // todo 优先级
	clk := eventclock.Real{}
	return NewTestable(TestableConfig{
		Name:                   "Controller",
		Clock:                  clk,
		AsFieldManager:         ConfigConsumerAsFieldManager,
		FoundToDangling:        func(found bool) bool { return !found },
		InformerFactory:        informerFactory,
		FlowcontrolClient:      flowcontrolClient,
		ServerConcurrencyLimit: serverConcurrencyLimit,
		RequestWaitLimit:       requestWaitLimit,
		ReqsGaugeVec:           metrics.PriorityLevelConcurrencyGaugeVec,
		ExecSeatsGaugeVec:      metrics.PriorityLevelExecutionSeatsGaugeVec,
		QueueSetFactory:        fqs.NewQueueSetFactory(clk), // ✅ 两个按钮用于设置数据(只能一次),   在设置前阻塞读
	})
}

type TestableConfig struct {
	Name                   string
	Clock                  clock.PassiveClock                            // 用于计时故意延迟。
	AsFieldManager         string                                        // 是在服务器端应用程序元数据中使用的字符串。通常为ConfigConsumerAsFieldManager。这是作为参数公开的，以便竞争控制器的测试可以提供不同的值。
	FoundToDangling        func(bool) bool                               // FoundToDangling将布尔值映射到布尔值，指示FlowSchema引用的PLC是否存在，以及该FlowSchema的状态是否应指示悬空引用。
	InformerFactory        kubeinformers.SharedInformerFactory           // 用于构建控制器的工具。
	FlowcontrolClient      flowcontrolclient.FlowcontrolV1beta3Interface // 用于操作配置对象的工具。
	ServerConcurrencyLimit int                                           //
	RequestWaitLimit       time.Duration                                 // 服务器端配置的
	ReqsGaugeVec           metrics.RatioedGaugeVec                       // 用于按阶段和优先级级别细分的请求度量。
	ExecSeatsGaugeVec      metrics.RatioedGaugeVec                       // 用于关于执行所有阶段占用的座位的度量。
	QueueSetFactory        fq.QueueSetFactory                            // 队列的实现   // ✅ 两个按钮用于设置数据(只能一次),   在设置前阻塞读
}

// NewTestable 非常灵活，以便于测试。
func NewTestable(config TestableConfig) Interface {
	return newTestableController(config)
}

func (cfgCtlr *configController) Handle(
	ctx context.Context,
	requestDigest RequestDigest,
	noteFn func(fs *flowcontrol.FlowSchema, pl *flowcontrol.PriorityLevelConfiguration, flowDistinguisher string),
	workEstimator func() fcrequest.WorkEstimate,
	queueNoteFn fq.QueueNoteFn,
	execFn func(),
) {
	fs, pl, isExempt, req, startWaitingTime := cfgCtlr.startRequest(ctx, requestDigest, noteFn, workEstimator, queueNoteFn)
	queued := startWaitingTime != time.Time{}
	if req == nil {
		if queued {
			metrics.ObserveWaitingDuration(ctx, pl.Name, fs.Name, strconv.FormatBool(req != nil), time.Since(startWaitingTime))
		}
		klog.V(7).Infof("Handle(%#+v) => fsName=%q, distMethod=%#+v, plName=%q, isExempt=%v, reject", requestDigest, fs.Name, fs.Spec.DistinguisherMethod, pl.Name, isExempt)
		return
	}
	klog.V(7).Infof("Handle(%#+v) => fsName=%q, distMethod=%#+v, plName=%q, isExempt=%v, queued=%v", requestDigest, fs.Name, fs.Spec.DistinguisherMethod, pl.Name, isExempt, queued)
	var executed bool
	idle, panicking := true, true
	defer func() {
		klog.V(7).Infof("Handle(%#+v) => fsName=%q, distMethod=%#+v, plName=%q, isExempt=%v, queued=%v, Finish() => panicking=%v idle=%v",
			requestDigest, fs.Name, fs.Spec.DistinguisherMethod, pl.Name, isExempt, queued, panicking, idle)
		if idle {
			cfgCtlr.maybeReap(pl.Name)
		}
	}()
	idle = req.Finish(func() {
		if queued {
			metrics.ObserveWaitingDuration(ctx, pl.Name, fs.Name, strconv.FormatBool(req != nil), time.Since(startWaitingTime))
		}
		metrics.AddDispatch(ctx, pl.Name, fs.Name)
		executed = true
		startExecutionTime := time.Now()
		defer func() {
			executionTime := time.Since(startExecutionTime)
			httplog.AddKeyValue(ctx, "apf_execution_time", executionTime)
			metrics.ObserveExecutionDuration(ctx, pl.Name, fs.Name, executionTime)
		}()
		execFn()
	})
	if queued && !executed {
		metrics.ObserveWaitingDuration(ctx, pl.Name, fs.Name, strconv.FormatBool(req != nil), time.Since(startWaitingTime))
	}
	panicking = false
}
