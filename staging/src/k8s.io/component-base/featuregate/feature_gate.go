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

package featuregate

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/spf13/pflag"

	"k8s.io/apimachinery/pkg/util/naming"
	featuremetrics "k8s.io/component-base/metrics/prometheus/feature"
	"k8s.io/klog/v2"
)

type Feature string

const (
	flagName = "feature-gates"

	// allAlphaGate is a global toggle for alpha features. Per-feature key
	// values override the default set by allAlphaGate. Examples:
	//   AllAlpha=false,NewFeature=true  will result in newFeature=true
	//   AllAlpha=true,NewFeature=false  will result in newFeature=false
	allAlphaGate Feature = "AllAlpha"

	// allBetaGate is a global toggle for beta features. Per-feature key
	// values override the default set by allBetaGate. Examples:
	//   AllBeta=false,NewFeature=true  will result in NewFeature=true
	//   AllBeta=true,NewFeature=false  will result in NewFeature=false
	allBetaGate Feature = "AllBeta"
)

var (
	// The generic features.
	defaultFeatures = map[Feature]FeatureSpec{
		allAlphaGate: {Default: false, PreRelease: Alpha},
		allBetaGate:  {Default: false, PreRelease: Beta},
	}

	// Special handling for a few gates.
	specialFeatures = map[Feature]func(known map[Feature]FeatureSpec, enabled map[Feature]bool, val bool){
		allAlphaGate: setUnsetAlphaGates,
		allBetaGate:  setUnsetBetaGates,
	}
)

type FeatureSpec struct {
	Default       bool       // 是该特性的默认启用状态
	LockToDefault bool       // 表示该特性被锁定为默认值,不能更改
	PreRelease    prerelease // 反映特性的成熟度级别
}

type prerelease string

const (
	Alpha = prerelease("ALPHA")
	Beta  = prerelease("BETA")
	GA    = prerelease("")

	// Deprecated
	Deprecated = prerelease("DEPRECATED")
)

// FeatureGate 指示是否启用给定的特性
type FeatureGate interface {
	// Enabled returns true if the key is enabled.
	Enabled(key Feature) bool
	// KnownFeatures returns a slice of strings describing the FeatureGate's known features.
	KnownFeatures() []string
	// DeepCopy returns a deep copy of the FeatureGate object, such that gates can be
	// set on the copy without mutating the original. This is useful for validating
	// config against potential feature gate changes before committing those changes.
	DeepCopy() MutableFeatureGate
}

// MutableFeatureGate 从字符串中解析和存储已知特性,例如feature1=true,feature2=false,…
type MutableFeatureGate interface {
	FeatureGate
	AddFlag(fs *pflag.FlagSet)                  // 为指定的 FlagSet 添加一个设置 功能开关 的flag.
	Set(value string) error                     // 为已知的特性设置解析值  feature1=true,feature2=false,...
	SetFromMap(m map[string]bool) error         // 为已知的特性设置解析值
	Add(features map[Feature]FeatureSpec) error // 添加特性
	GetAll() map[Feature]FeatureSpec            // 返回已知特性名称到特性规格的映射的副本
	AddMetrics()                                // 添加特性度量指标
}

// featureGate
type featureGate struct {
	featureGateName string
	special         map[Feature]func(map[Feature]FeatureSpec, map[Feature]bool, bool)
	lock            sync.Mutex
	known           *atomic.Value // 已知的特性
	enabled         *atomic.Value // 已启用的特性
	closed          bool          // 当AddFlag被调用时,closed被设置为true,并阻止后续对Add的调用
}

func setUnsetAlphaGates(known map[Feature]FeatureSpec, enabled map[Feature]bool, val bool) {
	for k, v := range known {
		if v.PreRelease == Alpha {
			if _, found := enabled[k]; !found {
				enabled[k] = val
			}
		}
	}
}

func setUnsetBetaGates(known map[Feature]FeatureSpec, enabled map[Feature]bool, val bool) {
	for k, v := range known {
		if v.PreRelease == Beta {
			if _, found := enabled[k]; !found {
				enabled[k] = val
			}
		}
	}
}

// Set, String, and Type implement pflag.Value
var _ pflag.Value = &featureGate{}

// internalPackages are packages that ignored when creating a name for featureGates. These packages are in the common
// call chains, so they'd be unhelpful as names.
var internalPackages = []string{"k8s.io/component-base/featuregate/feature_gate.go"}

func NewFeatureGate() *featureGate {
	known := map[Feature]FeatureSpec{}
	for k, v := range defaultFeatures {
		known[k] = v
	}

	knownValue := &atomic.Value{}
	knownValue.Store(known)

	enabled := map[Feature]bool{}
	enabledValue := &atomic.Value{}
	enabledValue.Store(enabled)

	f := &featureGate{
		featureGateName: naming.GetNameFromCallsite(internalPackages...),
		known:           knownValue,
		special:         specialFeatures,
		enabled:         enabledValue,
	}
	return f
}

// Set parses a string of the form "key1=value1,key2=value2,..." into a
// map[string]bool of known keys or returns an error.
func (f *featureGate) Set(value string) error {
	m := make(map[string]bool)
	for _, s := range strings.Split(value, ",") {
		if len(s) == 0 {
			continue
		}
		arr := strings.SplitN(s, "=", 2)
		k := strings.TrimSpace(arr[0])
		if len(arr) != 2 {
			return fmt.Errorf("missing bool value for %s", k)
		}
		v := strings.TrimSpace(arr[1])
		boolValue, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("invalid value of %s=%s, err: %v", k, v, err)
		}
		m[k] = boolValue
	}
	return f.SetFromMap(m)
}

// SetFromMap stores flag gates for known features from a map[string]bool or returns an error
func (f *featureGate) SetFromMap(m map[string]bool) error {
	f.lock.Lock()
	defer f.lock.Unlock()

	// Copy existing state
	known := map[Feature]FeatureSpec{}
	for k, v := range f.known.Load().(map[Feature]FeatureSpec) {
		known[k] = v
	}
	enabled := map[Feature]bool{}
	for k, v := range f.enabled.Load().(map[Feature]bool) {
		enabled[k] = v
	}

	for k, v := range m {
		k := Feature(k)
		featureSpec, ok := known[k]
		if !ok {
			return fmt.Errorf("unrecognized feature gate: %s", k)
		}
		if featureSpec.LockToDefault && featureSpec.Default != v {
			return fmt.Errorf("cannot set feature gate %v to %v, feature is locked to %v", k, v, featureSpec.Default)
		}
		enabled[k] = v
		// Handle "special" features like "all alpha gates"
		if fn, found := f.special[k]; found {
			fn(known, enabled, v)
		}

		if featureSpec.PreRelease == Deprecated {
			klog.Warningf("设置 弃用的功能开关 %s=%t. 它将在未来的版本中被删除.", k, v)
		} else if featureSpec.PreRelease == GA {
			klog.Warningf("设置 GA 功能开关 %s=%t. 它将在未来的版本中被删除.", k, v)
		}
	}

	// Persist changes
	f.known.Store(known)
	f.enabled.Store(enabled)

	klog.V(1).Infof("feature gates: %v", f.enabled)
	return nil
}

// String returns a string containing all enabled feature gates, formatted as "key1=value1,key2=value2,...".
func (f *featureGate) String() string {
	pairs := []string{}
	for k, v := range f.enabled.Load().(map[Feature]bool) {
		pairs = append(pairs, fmt.Sprintf("%s=%t", k, v))
	}
	sort.Strings(pairs)
	return strings.Join(pairs, ",")
}

func (f *featureGate) Type() string {
	return "mapStringBool"
}

// Add adds features to the featureGate.
func (f *featureGate) Add(features map[Feature]FeatureSpec) error {
	f.lock.Lock()
	defer f.lock.Unlock()

	if f.closed {
		return fmt.Errorf("cannot add a feature gate after adding it to the flag set")
	}

	// Copy existing state
	known := map[Feature]FeatureSpec{}
	for k, v := range f.known.Load().(map[Feature]FeatureSpec) {
		known[k] = v
	}

	for name, spec := range features {
		if existingSpec, found := known[name]; found {
			if existingSpec == spec {
				continue
			}
			return fmt.Errorf("feature gate %q with different spec already exists: %v", name, existingSpec)
		}

		known[name] = spec
	}

	// Persist updated state
	f.known.Store(known)

	return nil
}

// GetAll 返回已知特性名称到特性规格的映射的副本
func (f *featureGate) GetAll() map[Feature]FeatureSpec {
	retval := map[Feature]FeatureSpec{}
	for k, v := range f.known.Load().(map[Feature]FeatureSpec) {
		retval[k] = v
	}
	return retval
}

// Enabled 该特性是否启用
func (f *featureGate) Enabled(key Feature) bool {
	if v, ok := f.enabled.Load().(map[Feature]bool)[key]; ok {
		return v
	}
	if v, ok := f.known.Load().(map[Feature]FeatureSpec)[key]; ok {
		return v.Default
	}

	panic(fmt.Errorf("feature %q is not registered in FeatureGate %q", key, f.featureGateName))
}

// AddFlag adds a flag for setting global feature gates to the specified FlagSet.
func (f *featureGate) AddFlag(fs *pflag.FlagSet) {
	f.lock.Lock()
	// TODO(mtaufen): Shouldn't we just close it on the first Set/SetFromMap instead?
	// Not all components expose a feature gates flag using this AddFlag method, and
	// in the future, all components will completely stop exposing a feature gates flag,
	// in favor of componentconfig.
	f.closed = true
	f.lock.Unlock()

	known := f.KnownFeatures()
	fs.Var(f, flagName, "key=value 键值对集合,描述了特性功能\n"+strings.Join(known, "\n"))
}

// AddMetrics 初始化指标的计数器
func (f *featureGate) AddMetrics() {
	for feature, featureSpec := range f.GetAll() {
		featuremetrics.RecordFeatureInfo(context.Background(), string(feature), string(featureSpec.PreRelease), f.Enabled(feature))
	}
}

// KnownFeatures returns a slice of strings describing the FeatureGate's known features.
// Deprecated and GA features are hidden from the list.
func (f *featureGate) KnownFeatures() []string {
	var known []string
	for k, v := range f.known.Load().(map[Feature]FeatureSpec) {
		if v.PreRelease == GA || v.PreRelease == Deprecated {
			continue
		}
		known = append(known, fmt.Sprintf("%s=true|false (%s - default=%t)", k, v.PreRelease, v.Default))
	}
	sort.Strings(known)
	return known
}

// DeepCopy returns a deep copy of the FeatureGate object, such that gates can be
// set on the copy without mutating the original. This is useful for validating
// config against potential feature gate changes before committing those changes.
func (f *featureGate) DeepCopy() MutableFeatureGate {
	// Copy existing state.
	known := map[Feature]FeatureSpec{}
	for k, v := range f.known.Load().(map[Feature]FeatureSpec) {
		known[k] = v
	}
	enabled := map[Feature]bool{}
	for k, v := range f.enabled.Load().(map[Feature]bool) {
		enabled[k] = v
	}

	// Store copied state in new atomics.
	knownValue := &atomic.Value{}
	knownValue.Store(known)
	enabledValue := &atomic.Value{}
	enabledValue.Store(enabled)

	// Construct a new featureGate around the copied state.
	// Note that specialFeatures is treated as immutable by convention,
	// and we maintain the value of f.closed across the copy.
	return &featureGate{
		special: specialFeatures,
		known:   knownValue,
		enabled: enabledValue,
		closed:  f.closed,
	}
}
