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

package options

import (
	"github.com/spf13/pflag"

	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/server"
)

type FeatureOptions struct {
	EnableProfiling           bool
	EnableContentionProfiling bool
}

func NewFeatureOptions() *FeatureOptions {
	defaults := server.NewConfig(serializer.CodecFactory{})

	return &FeatureOptions{
		EnableProfiling:           defaults.EnableProfiling,
		EnableContentionProfiling: defaults.EnableContentionProfiling,
	}
}

func (o *FeatureOptions) AddFlags(fs *pflag.FlagSet) {
	if o == nil {
		return
	}

	fs.BoolVar(&o.EnableProfiling, "profiling", o.EnableProfiling, "通过web界面主机:port/debug/pprof/启用分析")
	fs.BoolVar(&o.EnableContentionProfiling, "contention-profiling", o.EnableContentionProfiling, "如果启用了分析，则启用锁争用分析")
}

func (o *FeatureOptions) ApplyTo(c *server.Config) error {
	if o == nil {
		return nil
	}

	c.EnableProfiling = o.EnableProfiling
	c.EnableContentionProfiling = o.EnableContentionProfiling

	return nil
}

// Validate 👌🏻
func (o *FeatureOptions) Validate() []error {
	if o == nil {
		return nil
	}

	errs := []error{}
	return errs
}
