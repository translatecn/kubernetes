/*
Copyright 2021 The Kubernetes Authors.

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

package request

import (
	"math"
	"net/http"
	"net/url"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/klog/v2"
)

func newListWorkEstimator(countFn objectCountGetterFunc, config *WorkEstimatorConfig) WorkEstimatorFunc {
	estimator := &listWorkEstimator{
		config:        config,
		countGetterFn: countFn,
	}
	return estimator.estimate
}

type listWorkEstimator struct {
	config        *WorkEstimatorConfig
	countGetterFn objectCountGetterFunc // 获取每种资源的请求数量
}

// 预估、估算
func (e *listWorkEstimator) estimate(r *http.Request, flowSchemaName, priorityLevelName string) WorkEstimate {
	requestInfo, ok := apirequest.RequestInfoFrom(r.Context())
	if !ok {
		// no RequestInfo should never happen, but to be on the safe side
		// let's return maximumSeats
		return WorkEstimate{InitialSeats: e.config.MaximumSeats}
	}

	if requestInfo.Name != "" {
		// Requests with metadata.name specified are usually executed as get
		// requests in storage layer so their width should be 1.
		// Example of such list requests:
		// /apis/certificates.k8s.io/v1/certificatesigningrequests?fieldSelector=metadata.name%3Dcsr-xxs4m
		// /api/v1/namespaces/test/configmaps?fieldSelector=metadata.name%3Dbig-deployment-1&limit=500&resourceVersion=0
		return WorkEstimate{InitialSeats: e.config.MinimumSeats}
	}

	query := r.URL.Query()
	listOptions := metav1.ListOptions{}
	if err := metav1.Convert_url_Values_To_v1_ListOptions(&query, &listOptions, nil); err != nil {
		klog.ErrorS(err, "Failed to convert options while estimating work for the list request")
		// 这个请求注定会在验证层失败，为了保持一致，返回maximumSeats。
		return WorkEstimate{InitialSeats: e.config.MaximumSeats}
	}
	isListFromCache := !shouldListFromStorage(query, &listOptions) // 要不要从etcd 加载数据

	numStored, err := e.countGetterFn(key(requestInfo))
	switch {
	case err == ObjectCountStaleErr:
		// 对象计数过时表明出现了退化，因此我们应该在此处保守，并为此列表请求分配最大座位数。
		// 注意：如果删除了CRD，则其计数将首先变为过时状态，然后修剪器将最终从缓存中删除CRD。
		return WorkEstimate{InitialSeats: e.config.MaximumSeats}
	case err == ObjectCountNotFoundErr:
		// there are multiple scenarios in which we can see this error:
		//  a. the type is truly unknown, a typo on the caller's part.
		//  b. the count has gone stale for too long and the pruner
		//     has removed the type from the cache.
		//  c. the type is an aggregated resource that is served by a
		//     different apiserver (thus its object count is not updated)
		// we don't have a way to distinguish between those situations.
		// However, in case c, the request is delegated to a different apiserver,
		// and thus its cost for our server is minimal. To avoid the situation
		// when aggregated API calls are overestimated, we allocate the minimum
		// possible seats (see #109106 as an example when being more conservative
		// led to problems).
		return WorkEstimate{InitialSeats: e.config.MinimumSeats}
	case err != nil:
		// we should never be here since Get returns either ObjectCountStaleErr or
		// ObjectCountNotFoundErr, return maximumSeats to be on the safe side.
		klog.ErrorS(err, "Unexpected error from object count tracker")
		return WorkEstimate{InitialSeats: e.config.MaximumSeats}
	}

	limit := numStored
	if utilfeature.DefaultFeatureGate.Enabled(features.APIListChunking) && listOptions.Limit > 0 &&
		listOptions.Limit < numStored {
		limit = listOptions.Limit
	}
	// 估计要处理的对象
	var estimatedObjectsToBeProcessed int64

	switch {
	case isListFromCache:
		// TODO: For resources that implement indexes at the watchcache level,
		//  we need to adjust the cost accordingly
		estimatedObjectsToBeProcessed = numStored
	case listOptions.FieldSelector != "" || listOptions.LabelSelector != "":
		estimatedObjectsToBeProcessed = numStored + limit
	default:
		estimatedObjectsToBeProcessed = 2 * limit
	}
	// 目前，我们的粗略估计是为将由列表请求处理的每100个对象分配一个座位。我们将在未来的迭代中提出不同的转换函数公式和/或微调此数字。
	seats := uint64(math.Ceil(float64(estimatedObjectsToBeProcessed) / e.config.ObjectsPerSeat))

	// make sure we never return a seat of zero
	if seats < e.config.MinimumSeats {
		seats = e.config.MinimumSeats
	}
	if seats > e.config.MaximumSeats {
		seats = e.config.MaximumSeats
	}
	return WorkEstimate{InitialSeats: seats}
}

func key(requestInfo *apirequest.RequestInfo) string {
	groupResource := &schema.GroupResource{
		Group:    requestInfo.APIGroup,
		Resource: requestInfo.Resource,
	}
	return groupResource.String()
}

// NOTICE: Keep in sync with shouldDelegateList function in
//
//	staging/src/k8s.io/apiserver/pkg/storage/cacher/cacher.go
func shouldListFromStorage(query url.Values, opts *metav1.ListOptions) bool {
	resourceVersion := opts.ResourceVersion
	pagingEnabled := utilfeature.DefaultFeatureGate.Enabled(features.APIListChunking)
	hasContinuation := pagingEnabled && len(opts.Continue) > 0
	hasLimit := pagingEnabled && opts.Limit > 0 && resourceVersion != "0"
	return resourceVersion == "" || hasContinuation || hasLimit || opts.ResourceVersionMatch == metav1.ResourceVersionMatchExact
}
