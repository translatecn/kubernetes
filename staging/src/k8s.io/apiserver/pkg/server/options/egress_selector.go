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

package options

import (
	"fmt"

	"github.com/spf13/pflag"
	"k8s.io/utils/path"

	"k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/egressselector"
)

type EgressSelectorOptions struct {
	ConfigFile string // 具有api服务器出口选择器配置的文件路径。
}

// NewEgressSelectorOptions 选项是指向用于出口/连接的配置文件.这决定了哪些类型的请求使用出口/连接以及如何使用它.如果为空,API服务器将尝试直接使用网络连接.
func NewEgressSelectorOptions() *EgressSelectorOptions {
	return &EgressSelectorOptions{}
}

// AddFlags adds flags related to admission for a specific APIServer to the specified FlagSet
func (o *EgressSelectorOptions) AddFlags(fs *pflag.FlagSet) {
	if o == nil {
		return
	}

	fs.StringVar(&o.ConfigFile, "egress-selector-config-file", o.ConfigFile, "apiserver egress 选择器配置文件")
}

// ApplyTo ✅
func (o *EgressSelectorOptions) ApplyTo(c *server.Config) error {
	if o == nil {
		return nil
	}

	npConfig, err := egressselector.ReadEgressSelectorConfiguration(o.ConfigFile)
	if err != nil {
		return fmt.Errorf("failed to read egress selector config: %v", err)
	}
	errs := egressselector.ValidateEgressSelectorConfiguration(npConfig)
	if len(errs) > 0 {
		return fmt.Errorf("failed to validate egress selector configuration: %v", errs.ToAggregate())
	}

	cs, err := egressselector.NewEgressSelector(npConfig) // ✅
	if err != nil {
		return fmt.Errorf("failed to setup egress selector with config %#v: %v", npConfig, err)
	}
	c.EgressSelector = cs
	return nil
}

// Validate verifies flags passed to EgressSelectorOptions.
func (o *EgressSelectorOptions) Validate() []error {
	if o == nil || o.ConfigFile == "" {
		return nil
	}

	errs := []error{}

	if exists, err := path.Exists(path.CheckFollowSymlink, o.ConfigFile); !exists || err != nil {
		errs = append(errs, fmt.Errorf("egress-selector-config-file %s does not exist", o.ConfigFile))
	}

	return errs
}
