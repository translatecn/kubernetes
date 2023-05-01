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

package record

import (
	"fmt"
	"math/rand"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/watch"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record/util"
	ref "k8s.io/client-go/tools/reference"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
)

const maxTriesPerEvent = 12

var defaultSleepDuration = 10 * time.Second

const maxQueuedEvents = 1000

// EventSink knows how to store events (client.Client implements it.)
// EventSink must respect the namespace that will be embedded in 'event'.
// It is assumed that EventSink will return the same sorts of errors as
// pkg/client's REST client.
type EventSink interface {
	Create(event *v1.Event) (*v1.Event, error)
	Update(event *v1.Event) (*v1.Event, error)
	Patch(oldEvent *v1.Event, data []byte) (*v1.Event, error)
}

// CorrelatorOptions 用于聚合和过滤事件
type CorrelatorOptions struct {
	LRUCacheSize         int                        // 用于 EventSourceObjectSpamFilter 和 EventAggregator 的 LRU 缓存大小。
	BurstSize            int                        // 事件令牌桶速率过滤器中使用的突发大小。
	QPS                  float32                    // 事件令牌桶中的查询速率（每秒）。
	KeyFunc              EventAggregatorKeyFunc     // 用于聚合事件键的函数。
	MessageFunc          EventAggregatorMessageFunc // 用于生成聚合消息的函数。
	MaxEvents            int                        // 在聚合之前的一个时间间隔内的事件数。
	MaxIntervalInSeconds int                        // 自上一个类似事件发生以来必须经过的时间（以秒为单位），才能被 EventAggregator 视为新事件。
	Clock                clock.PassiveClock         //
	SpamKeyFunc          EventSpamKeyFunc           // 使用的函数，根据给定事件返回一个键，基于该键进行过滤。
}

type EventRecorder interface {
	Event(object runtime.Object, eventtype, reason, message string)
	Eventf(object runtime.Object, eventtype, reason, messageFmt string, args ...interface{})
	AnnotatedEventf(object runtime.Object, annotations map[string]string, eventtype, reason, messageFmt string, args ...interface{})
}

// EventBroadcaster knows how to receive events and send them to any EventSink, watcher, or log.
type EventBroadcaster interface {
	StartEventWatcher(eventHandler func(*v1.Event)) watch.Interface             // 启动一个新的事件监听器
	StartRecordingToSink(sink EventSink) watch.Interface                        // 设置要发送到的名称空间
	StartLogging(logf func(format string, args ...interface{})) watch.Interface //
	StartStructuredLogging(verbosity klog.Level) watch.Interface                // 设置结构化日志等级阈值
	NewRecorder(scheme *runtime.Scheme, source v1.EventSource) EventRecorder    // 用于发送事件
	Shutdown()
}

// EventRecorderAdapter is a wrapper around a "k8s.io/client-go/tools/record".EventRecorder
// implementing the new "k8s.io/client-go/tools/events".EventRecorder interface.
type EventRecorderAdapter struct {
	recorder EventRecorder
}

// NewEventRecorderAdapter returns an adapter implementing the new
// "k8s.io/client-go/tools/events".EventRecorder interface.
func NewEventRecorderAdapter(recorder EventRecorder) *EventRecorderAdapter {
	return &EventRecorderAdapter{
		recorder: recorder,
	}
}

// Eventf is a wrapper around v1 Eventf
func (a *EventRecorderAdapter) Eventf(regarding, _ runtime.Object, eventtype, reason, action, note string, args ...interface{}) {
	a.recorder.Eventf(regarding, eventtype, reason, note, args...)
}

func NewBroadcaster() EventBroadcaster {
	return &eventBroadcasterImpl{
		Broadcaster:   watch.NewLongQueueBroadcaster(maxQueuedEvents, watch.DropIfChannelFull), // ✅
		sleepDuration: defaultSleepDuration,
	}
}

func NewBroadcasterForTests(sleepDuration time.Duration) EventBroadcaster {
	return &eventBroadcasterImpl{
		Broadcaster:   watch.NewLongQueueBroadcaster(maxQueuedEvents, watch.DropIfChannelFull),
		sleepDuration: sleepDuration,
	}
}

type eventBroadcasterImpl struct {
	*watch.Broadcaster
	sleepDuration time.Duration
	options       CorrelatorOptions
}

func (e *eventBroadcasterImpl) StartRecordingToSink(sink EventSink) watch.Interface {
	eventCorrelator := NewEventCorrelatorWithOptions(e.options)
	return e.StartEventWatcher( // 会生成一个新的watcher
		func(event *v1.Event) {
			recordToSink(sink, event, eventCorrelator, e.sleepDuration)
		})
}

func (e *eventBroadcasterImpl) Shutdown() {
	e.Broadcaster.Shutdown()
}

// 将事件发送到指定的目标
func recordToSink(sink EventSink, event *v1.Event, eventCorrelator *EventCorrelator, sleepDuration time.Duration) {
	// Make a copy before modification, because there could be multiple listeners.
	// Events are safe to copy like this.
	eventCopy := *event
	event = &eventCopy
	result, err := eventCorrelator.EventCorrelate(event)
	if err != nil {
		utilruntime.HandleError(err)
	}
	if result.Skip {
		return
	}
	tries := 0
	for {
		if recordEvent(sink, result.Event, result.Patch, result.Event.Count > 1, eventCorrelator) {
			break
		}
		tries++
		if tries >= maxTriesPerEvent {
			klog.Errorf("Unable to write event '%#v' (retry limit exceeded!)", event)
			break
		}
		// Randomize the first sleep so that various clients won't all be
		// synced up if the master goes down.
		if tries == 1 {
			time.Sleep(time.Duration(float64(sleepDuration) * rand.Float64()))
		} else {
			time.Sleep(sleepDuration)
		}
	}
}

// recordEvent attempts to write event to a sink. It returns true if the event
// was successfully recorded or discarded, false if it should be retried.
// If updateExistingEvent is false, it creates a new event, otherwise it updates
// existing event.
func recordEvent(sink EventSink, event *v1.Event, patch []byte, updateExistingEvent bool, eventCorrelator *EventCorrelator) bool {
	var newEvent *v1.Event
	var err error
	if updateExistingEvent {
		newEvent, err = sink.Patch(event, patch)
	}
	// 更新可能会失败，因为该事件可能已被删除，因此不再存在。
	if !updateExistingEvent || (updateExistingEvent && util.IsKeyNotFoundError(err)) {
		// Making sure that ResourceVersion is empty on creation
		event.ResourceVersion = ""
		newEvent, err = sink.Create(event)
	}
	if err == nil {
		// we need to update our event correlator with the server returned state to handle name/resourceversion
		eventCorrelator.UpdateState(newEvent)
		return true
	}

	// If we can't contact the server, then hold everything while we keep trying.
	// Otherwise, something about the event is malformed and we should abandon it.
	switch err.(type) {
	case *restclient.RequestConstructionError:
		// We will construct the request the same next time, so don't keep trying.
		klog.Errorf("Unable to construct event '%#v': '%v' (will not retry!)", event, err)
		return true
	case *errors.StatusError:
		if errors.IsAlreadyExists(err) {
			klog.V(5).Infof("Server rejected event '%#v': '%v' (will not retry!)", event, err)
		} else {
			klog.Errorf("Server rejected event '%#v': '%v' (will not retry!)", event, err)
		}
		return true
	case *errors.UnexpectedObjectError:
		// We don't expect this; it implies the server's response didn't match a
		// known pattern. Go ahead and retry.
	default:
		// This case includes actual http transport errors. Go ahead and retry.
	}
	klog.Errorf("Unable to write event: '%#v': '%v'(may retry after sleeping)", event, err)
	return false
}

func (e *eventBroadcasterImpl) StartLogging(logf func(format string, args ...interface{})) watch.Interface {
	return e.StartEventWatcher(
		func(e *v1.Event) {
			logf("Event(%#v): type: '%v' reason: '%v' %v", e.InvolvedObject, e.Type, e.Reason, e.Message)
		})
}

// StartStructuredLogging 打印日志到终端
func (e *eventBroadcasterImpl) StartStructuredLogging(verbosity klog.Level) watch.Interface {
	return e.StartEventWatcher(
		func(e *v1.Event) {
			klog.V(verbosity).InfoS("Event 发生", "object", klog.KRef(e.InvolvedObject.Namespace, e.InvolvedObject.Name),
				"fieldPath", e.InvolvedObject.FieldPath, "kind", e.InvolvedObject.Kind, "apiVersion", e.InvolvedObject.APIVersion, "type", e.Type, "reason", e.Reason, "message", e.Message)
		})
}

func (e *eventBroadcasterImpl) StartEventWatcher(eventHandler func(*v1.Event)) watch.Interface {
	watcher, err := e.Watch()
	if err != nil {
		klog.Errorf("Unable start event watcher: '%v' (will not retry!)", err)
	}
	go func() {
		defer utilruntime.HandleCrash()
		for watchEvent := range watcher.ResultChan() {
			event, ok := watchEvent.Object.(*v1.Event)
			if !ok {
				// This is all local, so there's no reason this should
				// ever happen.
				continue
			}
			eventHandler(event)
		}
	}()
	return watcher
}

// NewRecorder returns an EventRecorder that records events with the given event source.
func (e *eventBroadcasterImpl) NewRecorder(scheme *runtime.Scheme, source v1.EventSource) EventRecorder {
	return &recorderImpl{scheme, source, e.Broadcaster, clock.RealClock{}}
}

type recorderImpl struct {
	scheme *runtime.Scheme
	source v1.EventSource
	*watch.Broadcaster
	clock clock.PassiveClock
}

func (recorder *recorderImpl) generateEvent(object runtime.Object, annotations map[string]string, eventtype, reason, message string) {
	ref, err := ref.GetReference(recorder.scheme, object)
	if err != nil {
		klog.Errorf("Could not construct reference to: '%#v' due to: '%v'. Will not report event: '%v' '%v' '%v'", object, err, eventtype, reason, message)
		return
	}

	if !util.ValidateEventType(eventtype) {
		klog.Errorf("Unsupported event type: '%v'", eventtype)
		return
	}

	event := recorder.makeEvent(ref, annotations, eventtype, reason, message)
	event.Source = recorder.source

	// 注意:事件应该是一个非阻塞操作，但我们也不需要把它放在一个例程中，否则当我们关闭这个广播器时，我们会竞相写一个关闭的通道。
	// 如果我们超载了，就丢弃事件，如果发生了，就记录一个错误(我们已经配置了广播器来丢弃传出的事件)。
	sent, err := recorder.ActionOrDrop(watch.Added, event)
	if err != nil {
		klog.Errorf("unable to record event: %v (will not retry!)", err)
		return
	}
	if !sent {
		klog.Errorf("unable to record event: too many queued events, dropped event %#v", event)
	}
}

func (recorder *recorderImpl) Event(object runtime.Object, eventtype, reason, message string) {
	recorder.generateEvent(object, nil, eventtype, reason, message)
}

func (recorder *recorderImpl) Eventf(object runtime.Object, eventtype, reason, messageFmt string, args ...interface{}) {
	recorder.Event(object, eventtype, reason, fmt.Sprintf(messageFmt, args...))
}

func (recorder *recorderImpl) AnnotatedEventf(object runtime.Object, annotations map[string]string, eventtype, reason, messageFmt string, args ...interface{}) {
	recorder.generateEvent(object, annotations, eventtype, reason, fmt.Sprintf(messageFmt, args...))
}

func (recorder *recorderImpl) makeEvent(ref *v1.ObjectReference, annotations map[string]string, eventtype, reason, message string) *v1.Event {
	t := metav1.Time{Time: recorder.clock.Now()}
	namespace := ref.Namespace
	if namespace == "" {
		namespace = metav1.NamespaceDefault
	}
	return &v1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:        fmt.Sprintf("%v.%x", ref.Name, t.UnixNano()),
			Namespace:   namespace,
			Annotations: annotations,
		},
		InvolvedObject: *ref,
		Reason:         reason,
		Message:        message,
		FirstTimestamp: t,
		LastTimestamp:  t,
		Count:          1,
		Type:           eventtype,
	}
}
