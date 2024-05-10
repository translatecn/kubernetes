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
	"math"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type RateLimiter interface {
	When(item interface{}) time.Duration // 获取一个项目并决定该项目应该等待多长时间
	Forget(item interface{})             // 指示项已完成重试.不管是成功还是失败,我们都会停止追踪
	NumRequeues(item interface{}) int    // 返回项目失败的次数
}

// ---------------------------------------------默认----------------------------------------------

// DefaultControllerRateLimiter 是工作队列的默认速率限制器的无参数构造函数.它有整体和每件物品的速度限制.整体是一个令牌桶,每一项是指数级的
func DefaultControllerRateLimiter() RateLimiter {
	return NewMaxOfRateLimiter(
		NewItemExponentialFailureRateLimiter(5*time.Millisecond, 1000*time.Second),
		&BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(10), 100)},
	)
}
func NewMaxOfRateLimiter(limiters ...RateLimiter) RateLimiter {
	return &MaxOfRateLimiter{limiters: limiters}
}

// MaxOfRateLimiter 当与令牌桶限制器一起使用时,在特定项单独延迟较长时间的情况下,爆发可能会明显超过.
type MaxOfRateLimiter struct {
	limiters []RateLimiter
}

func (r *MaxOfRateLimiter) When(item interface{}) time.Duration { // 取较大者
	ret := time.Duration(0)
	for _, limiter := range r.limiters {
		curr := limiter.When(item)
		if curr > ret {
			ret = curr
		}
	}

	return ret
}

func (r *MaxOfRateLimiter) NumRequeues(item interface{}) int { // 取较大者
	ret := 0
	for _, limiter := range r.limiters {
		curr := limiter.NumRequeues(item)
		if curr > ret {
			ret = curr
		}
	}

	return ret
}

func (r *MaxOfRateLimiter) Forget(item interface{}) {
	for _, limiter := range r.limiters {
		limiter.Forget(item)
	}
}

// --------------------------------------------默认 ok-----------------------------------------------

// ItemExponentialFailureRateLimiter 做一个简单的baseDelay*2^<num-failures>限制;对Max失败和过期的限制处理由调用者决定
type ItemExponentialFailureRateLimiter struct {
	failuresLock sync.Mutex
	failures     map[interface{}]int

	baseDelay time.Duration
	maxDelay  time.Duration
}

var _ RateLimiter = &ItemExponentialFailureRateLimiter{}

func NewItemExponentialFailureRateLimiter(baseDelay time.Duration, maxDelay time.Duration) RateLimiter {
	return &ItemExponentialFailureRateLimiter{
		failures:  map[interface{}]int{},
		baseDelay: baseDelay,
		maxDelay:  maxDelay,
	}
}

func (r *ItemExponentialFailureRateLimiter) When(item interface{}) time.Duration {
	r.failuresLock.Lock()
	defer r.failuresLock.Unlock()

	exp := r.failures[item]
	r.failures[item] = r.failures[item] + 1

	// 每调用一次,exp也就加1,对应到这里时2^n指数爆炸
	backoff := float64(r.baseDelay.Nanoseconds()) * math.Pow(2, float64(exp))
	if backoff > math.MaxInt64 {
		return r.maxDelay
	}

	calculated := time.Duration(backoff)
	if calculated > r.maxDelay {
		return r.maxDelay
	}

	return calculated
}

func (r *ItemExponentialFailureRateLimiter) NumRequeues(item interface{}) int {
	r.failuresLock.Lock()
	defer r.failuresLock.Unlock()

	return r.failures[item]
}

func (r *ItemExponentialFailureRateLimiter) Forget(item interface{}) {
	r.failuresLock.Lock()
	defer r.failuresLock.Unlock()

	delete(r.failures, item)
}

// -------------------------------------默认------------------------------------------------------

// BucketRateLimiter 将标准桶适配到工作队列速率限制器API
type BucketRateLimiter struct {
	*rate.Limiter
}

var _ RateLimiter = &BucketRateLimiter{}

func (r *BucketRateLimiter) When(item interface{}) time.Duration {
	// 过多久之后给当前元素发放一个令牌
	return r.Limiter.Reserve().Delay()
}

func (r *BucketRateLimiter) NumRequeues(item interface{}) int {
	return 0
}

func (r *BucketRateLimiter) Forget(item interface{}) {
}

// ---------------------------------------------ok----------------------------------------------

// ItemFastSlowRateLimiter 是否快速重试一定数量的尝试,然后缓慢重试之后
type ItemFastSlowRateLimiter struct {
	failuresLock    sync.Mutex
	failures        map[interface{}]int
	maxFastAttempts int           // 快速重试的次数
	fastDelay       time.Duration // 快重试间隔
	slowDelay       time.Duration // 慢重试间隔
}

var _ RateLimiter = &ItemFastSlowRateLimiter{}

func NewItemFastSlowRateLimiter(fastDelay, slowDelay time.Duration, maxFastAttempts int) RateLimiter {
	return &ItemFastSlowRateLimiter{
		failures:        map[interface{}]int{},
		fastDelay:       fastDelay,
		slowDelay:       slowDelay,
		maxFastAttempts: maxFastAttempts,
	}
}

func (r *ItemFastSlowRateLimiter) When(item interface{}) time.Duration {
	r.failuresLock.Lock()
	defer r.failuresLock.Unlock()

	r.failures[item] = r.failures[item] + 1
	// 如果快重试次数没有用完,返回fastDelay
	if r.failures[item] <= r.maxFastAttempts {
		return r.fastDelay
	}

	return r.slowDelay
}

func (r *ItemFastSlowRateLimiter) NumRequeues(item interface{}) int {
	r.failuresLock.Lock()
	defer r.failuresLock.Unlock()

	return r.failures[item]
}

func (r *ItemFastSlowRateLimiter) Forget(item interface{}) {
	r.failuresLock.Lock()
	defer r.failuresLock.Unlock()

	delete(r.failures, item)
}

// -------------------------------------------------------------------------------------------

// WithMaxWaitRateLimiter 有maxDelay避免等待太长时间
type WithMaxWaitRateLimiter struct {
	limiter  RateLimiter
	maxDelay time.Duration
}

func NewWithMaxWaitRateLimiter(limiter RateLimiter, maxDelay time.Duration) RateLimiter {
	return &WithMaxWaitRateLimiter{limiter: limiter, maxDelay: maxDelay}
}

func (w WithMaxWaitRateLimiter) When(item interface{}) time.Duration {
	delay := w.limiter.When(item)
	if delay > w.maxDelay {
		return w.maxDelay
	}

	return delay
}

func (w WithMaxWaitRateLimiter) Forget(item interface{}) {
	w.limiter.Forget(item)
}

func (w WithMaxWaitRateLimiter) NumRequeues(item interface{}) int {
	return w.limiter.NumRequeues(item)
}
