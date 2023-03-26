/*
Copyright 2017 The Kubernetes Authors.

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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sync/singleflight"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	auditinternal "k8s.io/apiserver/pkg/apis/audit"
	"k8s.io/apiserver/pkg/audit"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/warning"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
)

var errAuthnCrash = apierrors.NewInternalError(errors.New("authentication failed unexpectedly"))

const sharedLookupTimeout = 30 * time.Second

// cacheRecord holds the three return values of the authenticator.Token AuthenticateToken method
type cacheRecord struct {
	resp *authenticator.Response
	ok   bool
	err  error

	// this cache assumes token authn has no side-effects or temporal dependence.
	// neither of these are true for audit annotations set via AddAuditAnnotation.
	//
	// for audit annotations, the assumption is that for some period of time (cache TTL),
	// all requests with the same API audiences and the same bearer token result in the
	// same annotations.  This may not be true if the authenticator sets an annotation
	// based on the current time, but that may be okay since cache TTLs are generally
	// small (seconds).
	annotations map[string]string
	warnings    []*cacheWarning
}

type cacheWarning struct {
	agent string
	text  string
}

type cachedTokenAuthenticator struct {
	authenticator authenticator.Token
	cacheErrs     bool
	successTTL    time.Duration
	failureTTL    time.Duration
	cache         cache
	group         singleflight.Group
	hashPool      *sync.Pool // todo 暂时不知道具体有什么用途
}

type cache interface {
	// given a key, return the record, and whether or not it existed
	get(key string) (value *cacheRecord, exists bool)
	// caches the record for the key
	set(key string, value *cacheRecord, ttl time.Duration)
	// removes the record for the key
	remove(key string)
}

// New 返回令牌验证器，该验证器缓存指定验证器的结果。ttl为0会绕过缓存。
func New(authenticator authenticator.Token, cacheErrs bool, successTTL, failureTTL time.Duration) authenticator.Token {
	return newWithClock(authenticator, cacheErrs, successTTL, failureTTL, clock.RealClock{})
}

func newWithClock(authenticator authenticator.Token, cacheErrs bool, successTTL, failureTTL time.Duration, clock clock.Clock) authenticator.Token {
	randomCacheKey := make([]byte, 32)
	if _, err := rand.Read(randomCacheKey); err != nil {
		panic(err) // rand should never fail
	}

	return &cachedTokenAuthenticator{
		authenticator: authenticator,
		cacheErrs:     cacheErrs,
		successTTL:    successTTL,
		failureTTL:    failureTTL,
		//当正在操作的令牌数量超过缓存的大小时，缓存性能会显著降低。在下面的第二个维度中使缓存变大是很便宜的，只有在使用那么多令牌时才会消耗内存。
		//目前我们宣称支持5k个节点和10k个名称空间;因此，32k的入口缓存是2倍的安全裕度。
		cache: newStripedCache(32, fnvHashFunc, func() cache { return newSimpleCache(clock) }),
		hashPool: &sync.Pool{
			// hashPool 是每个验证者的散列池。哈希(避免在构建 Hash 时进行分配)
			//使用SHA-256和随机密钥的HMAC，防止预计算和扩长攻击
			//它还通过碰撞来减轻哈希映射DOS攻击(输入由不受信任的用户提供)
			New: func() interface{} {
				return hmac.New(sha256.New, randomCacheKey)
			},
		},
	}
}

// AuthenticateToken implements authenticator.Token
func (a *cachedTokenAuthenticator) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	record := a.doAuthenticateToken(ctx, token)
	if !record.ok || record.err != nil {
		return nil, false, record.err
	}
	for key, value := range record.annotations {
		audit.AddAuditAnnotation(ctx, key, value)
	}
	for _, w := range record.warnings {
		warning.AddWarning(ctx, w.agent, w.text)
	}
	return record.resp, true, nil
}

func (a *cachedTokenAuthenticator) doAuthenticateToken(ctx context.Context, token string) *cacheRecord {
	doneAuthenticating := stats.authenticating(ctx)

	auds, audsOk := authenticator.AudiencesFrom(ctx)

	key := keyFunc(a.hashPool, auds, token)
	if record, ok := a.cache.get(key); ok {
		// Record cache hit
		doneAuthenticating(true)
		return record
	}

	// Record cache miss
	doneBlocking := stats.blocking(ctx)
	defer doneBlocking()
	defer doneAuthenticating(false)

	c := a.group.DoChan(key, func() (val interface{}, _ error) {
		// always use one place to read and write the output of AuthenticateToken
		record := &cacheRecord{}

		doneFetching := stats.fetching(ctx)
		// We're leaving the request handling stack so we need to handle crashes
		// ourselves. Log a stack trace and return a 500 if something panics.
		defer func() {
			if r := recover(); r != nil {
				// make sure to always return a record
				record.err = errAuthnCrash
				val = record

				// Same as stdlib http server code. Manually allocate stack
				// trace buffer size to prevent excessively large logs
				const size = 64 << 10
				buf := make([]byte, size)
				buf = buf[:runtime.Stack(buf, false)]
				klog.Errorf("%v\n%s", r, buf)
			}
			doneFetching(record.err == nil)
		}()

		// Check again for a cached record. We may have raced with a fetch.
		if record, ok := a.cache.get(key); ok {
			return record, nil
		}

		// Detach the context because the lookup may be shared by multiple callers,
		// however propagate the audience.
		ctx, cancel := context.WithTimeout(context.Background(), sharedLookupTimeout)
		defer cancel()

		if audsOk {
			ctx = authenticator.WithAudiences(ctx, auds)
		}
		recorder := &recorder{}
		ctx = warning.WithWarningRecorder(ctx, recorder)

		// since this is shared work between multiple requests, we have no way of knowing if any
		// particular request supports audit annotations.  thus we always attempt to record them.
		ev := &auditinternal.Event{Level: auditinternal.LevelMetadata}
		ctx = audit.WithAuditContext(ctx)
		ac := audit.AuditContextFrom(ctx)
		ac.Event = ev

		record.resp, record.ok, record.err = a.authenticator.AuthenticateToken(ctx, token)
		record.annotations = ev.Annotations
		record.warnings = recorder.extractWarnings()

		if !a.cacheErrs && record.err != nil {
			return record, nil
		}

		switch {
		case record.ok && a.successTTL > 0:
			a.cache.set(key, record, a.successTTL)
		case !record.ok && a.failureTTL > 0:
			a.cache.set(key, record, a.failureTTL)
		}

		return record, nil
	})

	select {
	case result := <-c:
		// we always set Val and never set Err
		return result.Val.(*cacheRecord)
	case <-ctx.Done():
		// fake a record on context cancel
		return &cacheRecord{err: ctx.Err()}
	}
}

// keyFunc generates a string key by hashing the inputs.
// This lowers the memory requirement of the cache and keeps tokens out of memory.
func keyFunc(hashPool *sync.Pool, auds []string, token string) string {
	h := hashPool.Get().(hash.Hash)

	h.Reset()

	// try to force stack allocation
	var a [4]byte
	b := a[:]

	writeLengthPrefixedString(h, b, token)
	// encode the length of audiences to avoid ambiguities
	writeLength(h, b, len(auds))
	for _, aud := range auds {
		writeLengthPrefixedString(h, b, aud)
	}

	key := toString(h.Sum(nil)) // skip base64 encoding to save an allocation

	hashPool.Put(h)

	return key
}

// writeLengthPrefixedString writes s with a length prefix to prevent ambiguities, i.e. "xy" + "z" == "x" + "yz"
// the length of b is assumed to be 4 (b is mutated by this function to store the length of s)
func writeLengthPrefixedString(w io.Writer, b []byte, s string) {
	writeLength(w, b, len(s))
	if _, err := w.Write(toBytes(s)); err != nil {
		panic(err) // Write() on hash never fails
	}
}

// writeLength encodes length into b and then writes it via the given writer
// the length of b is assumed to be 4
func writeLength(w io.Writer, b []byte, length int) {
	binary.BigEndian.PutUint32(b, uint32(length))
	if _, err := w.Write(b); err != nil {
		panic(err) // Write() on hash never fails
	}
}

// toBytes performs unholy acts to avoid allocations
func toBytes(s string) []byte {
	return *(*[]byte)(unsafe.Pointer(&s))
}

// toString performs unholy acts to avoid allocations
func toString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

// simple recorder that only appends warning
type recorder struct {
	mu       sync.Mutex
	warnings []*cacheWarning
}

// AddWarning adds a warning to recorder.
func (r *recorder) AddWarning(agent, text string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.warnings = append(r.warnings, &cacheWarning{agent: agent, text: text})
}

func (r *recorder) extractWarnings() []*cacheWarning {
	r.mu.Lock()
	defer r.mu.Unlock()
	warnings := r.warnings
	r.warnings = nil
	return warnings
}
