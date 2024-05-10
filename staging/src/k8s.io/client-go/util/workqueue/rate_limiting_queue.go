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

// RateLimitingInterface 是一个接口,它对添加到队列中的项进行速率限制.
type RateLimitingInterface interface {
	DelayingInterface
	AddRateLimited(item interface{})  // AddRateLimited 限速方式往队列中加入一个元素
	Forget(item interface{})          // Forget 标识一个元素结束重试
	NumRequeues(item interface{}) int // NumRequeues 表示这个元素被处理了多少次
}

func NewRateLimitingQueue(rateLimiter RateLimiter) RateLimitingInterface {
	return &rateLimitingType{
		DelayingInterface: NewDelayingQueue(),
		rateLimiter:       rateLimiter,
	}
}

func NewNamedRateLimitingQueue(rateLimiter RateLimiter, name string) RateLimitingInterface {
	return &rateLimitingType{
		DelayingInterface: NewNamedDelayingQueue(name),
		rateLimiter:       rateLimiter,
	}
}

func NewRateLimitingQueueWithDelayingInterface(di DelayingInterface, rateLimiter RateLimiter) RateLimitingInterface {
	return &rateLimitingType{
		DelayingInterface: di,
		rateLimiter:       rateLimiter,
	}
}

type rateLimitingType struct {
	DelayingInterface
	rateLimiter RateLimiter
}

// AddRateLimited AddAfter's the item based on the time when the rate limiter says it's ok
func (q *rateLimitingType) AddRateLimited(item interface{}) {
	// 内部存储了一个延时队列,通过限速器计算出一个等待时间,然后传给延时队列
	q.DelayingInterface.AddAfter(item, q.rateLimiter.When(item))
}

func (q *rateLimitingType) NumRequeues(item interface{}) int {
	return q.rateLimiter.NumRequeues(item)
}

func (q *rateLimitingType) Forget(item interface{}) {
	q.rateLimiter.Forget(item)
}
