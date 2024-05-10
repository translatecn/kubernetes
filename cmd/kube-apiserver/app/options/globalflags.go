/*
Copyright 2018 The Kubernetes Authors.

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

	"k8s.io/component-base/cli/globalflag"

	// ensure libs have a chance to globally register their flags
	_ "k8s.io/apiserver/pkg/admission"
	_ "k8s.io/kubernetes/pkg/cloudprovider/providers"
)

func AddCustomGlobalFlags(fs *pflag.FlagSet) {

	// Adds flags from k8s.io/kubernetes/pkg/cloudprovider/providers.
	registerLegacyGlobalFlags(fs)

	// Adds flags from k8s.io/apiserver/pkg/admission.
	globalflag.Register(fs, "default-not-ready-toleration-seconds")
	globalflag.Register(fs, "default-unreachable-toleration-seconds")
}
