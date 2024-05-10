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

package metrics

import (
	"fmt"
	"regexp"

	"github.com/blang/semver/v4"
	"github.com/spf13/pflag"

	"k8s.io/component-base/version"
)

// Options has all parameters needed for exposing metrics from components
type Options struct {
	ShowHiddenMetricsForVersion string
	DisabledMetrics             []string
	AllowListMapping            map[string]string // 要显示的指标 <MetricName>,<LabelName>=<allowed_value>,<allowed_value>..
}

// NewOptions returns default metrics options
func NewOptions() *Options {
	return &Options{}
}

// Validate 👌🏻
func (o *Options) Validate() []error {
	var errs []error
	err := validateShowHiddenMetricsVersion(parseVersion(version.Get()), o.ShowHiddenMetricsForVersion) // 校验显示 隐藏指标的版本号 是不是前一个版本号
	if err != nil {
		errs = append(errs, err)
	}

	if err := validateAllowMetricLabel(o.AllowListMapping); err != nil {
		errs = append(errs, err)
	}

	if len(errs) == 0 {
		return nil
	}
	return errs
}

// AddFlags adds flags for exposing component metrics.
func (o *Options) AddFlags(fs *pflag.FlagSet) {
	if o == nil {
		return
	}
	fs.StringVar(&o.ShowHiddenMetricsForVersion, "show-hidden-metrics-for-version", o.ShowHiddenMetricsForVersion, "显示隐藏指标的前一个版本号 '1.16'. ")
	fs.StringSliceVar(&o.DisabledMetrics, "disabled-metrics", o.DisabledMetrics, "禁用哪些指标,免责声明:禁用指标优先级高于显示隐藏指标.")
	fs.StringToStringVar(&o.AllowListMapping, "allow-metric-labels", o.AllowListMapping, "要显示的指标 <MetricName>,<LabelName>=<allowed_value>,<allowed_value>...")
}

// Apply applies parameters into global configuration of metrics.
func (o *Options) Apply() {
	if o == nil {
		return
	}
	if len(o.ShowHiddenMetricsForVersion) > 0 {
		SetShowHidden()
	}
	// set disabled metrics
	for _, metricName := range o.DisabledMetrics {
		SetDisabledMetric(metricName)
	}
	if o.AllowListMapping != nil {
		SetLabelAllowListFromCLI(o.AllowListMapping)
	}
}

func validateShowHiddenMetricsVersion(currentVersion semver.Version, targetVersionStr string) error {
	if targetVersionStr == "" {
		return nil
	}

	validVersionStr := fmt.Sprintf("%d.%d", currentVersion.Major, currentVersion.Minor-1)
	if targetVersionStr != validVersionStr {
		return fmt.Errorf("--show-hidden-metrics-for-version must be omitted or have the value '%v'. Only the previous minor version is allowed", validVersionStr)
	}

	return nil
}

func validateAllowMetricLabel(allowListMapping map[string]string) error {
	// 要显示的指标 <MetricName>,<LabelName>=<allowed_value>,<allowed_value>..
	if allowListMapping == nil {
		return nil
	}
	metricNameRegex := `[a-zA-Z_:][a-zA-Z0-9_:]*`
	labelRegex := `[a-zA-Z_][a-zA-Z0-9_]*`
	for k := range allowListMapping {
		reg := regexp.MustCompile(metricNameRegex + `,` + labelRegex)
		if reg.FindString(k) != k {
			return fmt.Errorf("--allow-metric-labels must has a list of kv pair with format `metricName:labelName=labelValue, labelValue,...`")
		}
	}
	return nil
}
