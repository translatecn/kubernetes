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

package workqueue

import (
	"container/heap"
	"sync"
	"time"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/utils/clock"
)

// DelayingInterface is an Interface that can Add an item at a later time. This makes it easier to
// requeue items after failures without ending up in a hot-loop.
type DelayingInterface interface {
	Interface
	// AddAfter adds an item to the workqueue after the indicated duration has passed
	AddAfter(item interface{}, duration time.Duration)
}

// NewDelayingQueue constructs a new workqueue with delayed queuing ability.
// NewDelayingQueue does not emit metrics. For use with a MetricsProvider, please use
// NewNamedDelayingQueue instead.
func NewDelayingQueue() DelayingInterface {
	return NewDelayingQueueWithCustomClock(clock.RealClock{}, "")
}

// NewNamedDelayingQueue constructs a new named workqueue with delayed queuing ability
func NewNamedDelayingQueue(name string) DelayingInterface {
	return NewDelayingQueueWithCustomClock(clock.RealClock{}, name)
}

// NewDelayingQueueWithCustomClock constructs a new named workqueue
// with ability to inject real or fake clock for testing purposes
func NewDelayingQueueWithCustomClock(clock clock.WithTicker, name string) DelayingInterface {
	return newDelayingQueue(clock, NewNamed(name), name)
}

func newDelayingQueue(clock clock.WithTicker, q Interface, name string) *delayingType {
	ret := &delayingType{
		Interface:       q,
		clock:           clock,
		heartbeat:       clock.NewTicker(maxWait),
		stopCh:          make(chan struct{}),
		waitingForAddCh: make(chan *waitFor, 1000),
		metrics:         newRetryMetrics(name),
	}

	go ret.waitingLoop()
	return ret
}

// delayingType wraps an Interface and provides delayed re-enquing
type delayingType struct {
	Interface

	clock    clock.Clock // 计时器
	stopCh   chan struct{}
	stopOnce sync.Once

	// heartbeat ensures we wait no more than maxWait before firing
	heartbeat       clock.Ticker  // 镻认10秒的心跳,后面用在一个大循环里,避免没有新元素时一直阻塞
	waitingForAddCh chan *waitFor // 1000
	metrics         retryMetrics
}

// waitFor holds the data to add and the time it should be added
type waitFor struct {
	data    t         // 准备添加到队列中的数据
	readyAt time.Time // 应该被加入到队列的时间
	index   int       // 在heap中的索引
}

// waitForPriorityQueue implements a priority queue for waitFor items.
//
// waitForPriorityQueue implements heap.Interface. The item occurring next in
// time (i.e., the item with the smallest readyAt) is at the root (index 0).
// Peek returns this minimum item at index 0. Pop returns the minimum item after
// it has been removed from the queue and placed at index Len()-1 by
// container/heap. Push adds an item at index Len(), and container/heap
// percolates it into the correct location.
type waitForPriorityQueue []*waitFor

func (pq waitForPriorityQueue) Len() int {
	return len(pq)
}
func (pq waitForPriorityQueue) Less(i, j int) bool {
	return pq[i].readyAt.Before(pq[j].readyAt)
}
func (pq waitForPriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

// Push adds an item to the queue. Push should not be called directly; instead,
// use `heap.Push`.
func (pq *waitForPriorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*waitFor)
	item.index = n
	*pq = append(*pq, item)
}

// Pop removes an item from the queue. Pop should not be called directly;
// instead, use `heap.Pop`.
func (pq *waitForPriorityQueue) Pop() interface{} {
	n := len(*pq)
	item := (*pq)[n-1]
	item.index = -1
	*pq = (*pq)[0:(n - 1)]
	return item
}

// Peek returns the item at the beginning of the queue, without removing the
// item or otherwise mutating the queue. It is safe to call directly.
func (pq waitForPriorityQueue) Peek() interface{} {
	return pq[0]
}

// ShutDown stops the queue. After the queue drains, the returned shutdown bool
// on Get() will be true. This method may be invoked more than once.
func (q *delayingType) ShutDown() {
	q.stopOnce.Do(func() {
		q.Interface.ShutDown()
		close(q.stopCh)
		q.heartbeat.Stop()
	})
}

// AddAfter adds the given item to the work queue after the given delay
func (q *delayingType) AddAfter(item interface{}, duration time.Duration) {
	// don't add if we're already shutting down
	if q.ShuttingDown() {
		return
	}

	q.metrics.retry()

	if duration <= 0 { // 时间到了,直接添加
		q.Add(item)
		return
	}

	select {
	case <-q.stopCh:
		// unblock if ShutDown() is called
	case q.waitingForAddCh <- &waitFor{data: item, readyAt: q.clock.Now().Add(duration)}:
	}
}

// maxWait keeps a max bound on the wait time. It's just insurance against weird things happening.
// Checking the queue every 10 seconds isn't expensive and we know that we'll never end up with an
// expired item sitting for more than 10 seconds.
const maxWait = 10 * time.Second

// waitingLoop runs until the workqueue is shutdown and keeps a check on the list of items to be added.
func (q *delayingType) waitingLoop() {
	defer utilruntime.HandleCrash()

	// 队列里没有元素时实现等待
	never := make(<-chan time.Time)

	// 设置一个计时器,当队列最前面的物品准备好时,计时器就会过期
	var nextReadyAtTimer clock.Timer
	// 优先级队列
	waitingForQueue := &waitForPriorityQueue{}
	heap.Init(waitingForQueue)

	// 用来处理重复添加逻辑
	waitingEntryByData := map[t]*waitFor{}

	for {
		if q.Interface.ShuttingDown() {
			return
		}

		now := q.clock.Now()

		// 队列有元素就开始循环
		for waitingForQueue.Len() > 0 {
			entry := waitingForQueue.Peek().(*waitFor)
			if entry.readyAt.After(now) {
				break
			}
			// 时间到了,pop出最后一个元素
			entry = heap.Pop(waitingForQueue).(*waitFor)
			q.Add(entry.data)
			// 删除已经加入到延迟队列里的元素
			delete(waitingEntryByData, entry.data)
		}

		// 如果队列有元素,就用第一个原色的等待时间初始化计时器,如果为空则一直等待
		nextReadyAt := never
		if waitingForQueue.Len() > 0 {
			if nextReadyAtTimer != nil {
				nextReadyAtTimer.Stop()
			}
			entry := waitingForQueue.Peek().(*waitFor)
			nextReadyAtTimer = q.clock.NewTimer(entry.readyAt.Sub(now))
			nextReadyAt = nextReadyAtTimer.C()
		}

		select {
		case <-q.stopCh:
			return

		case <-q.heartbeat.C(): // 10秒
		case <-nextReadyAt: // 第一个元素的等待时间到了

		case waitEntry := <-q.waitingForAddCh:
			// 如果时间没到,就加到优先级队列里;如果时间到了,就加入到延时队列里
			if waitEntry.readyAt.After(q.clock.Now()) {
				insert(waitingForQueue, waitingEntryByData, waitEntry)
			} else {
				q.Add(waitEntry.data)
			}
			// 将waitingForAddCh里的数据处理完
			drained := false
			for !drained {
				select {
				case waitEntry := <-q.waitingForAddCh:
					if waitEntry.readyAt.After(q.clock.Now()) {
						insert(waitingForQueue, waitingEntryByData, waitEntry)
					} else {
						q.Add(waitEntry.data)
					}
				default:
					drained = true
				}
			}
		}
	}
}

// insert adds the entry to the priority queue, or updates the readyAt if it already exists in the queue
func insert(q *waitForPriorityQueue, knownEntries map[t]*waitFor, entry *waitFor) {
	// 看一个元素是够存在,如果存在,且新的到达时间早,就更新时间
	existing, exists := knownEntries[entry.data]
	if exists {
		if existing.readyAt.After(entry.readyAt) {
			existing.readyAt = entry.readyAt
			heap.Fix(q, existing.index)
		}

		return
	}

	heap.Push(q, entry)
	knownEntries[entry.data] = entry
}
