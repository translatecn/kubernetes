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

package v1

import (
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
)

// Supported output formats.
const (
	// DefaultLogFormat is the traditional klog output format.
	DefaultLogFormat = "text"

	// JSONLogFormat emits each log message as a JSON struct.
	JSONLogFormat = "json"
)

type LoggingConfiguration struct {
	Format         string               `json:"format,omitempty"`  // 日志格式，默认t
	FlushFrequency time.Duration        `json:"flushFrequency"`    // 两次日志刷新之间的最大纳秒数(即1s = 1000000000)。如果所选日志后端写入日志消息而没有缓冲，则忽略。
	Verbosity      VerbosityLevel       `json:"verbosity"`         // 是决定记录哪些日志消息的阈值。默认为0，只记录最重要的消息。更高的值可以启用其他消息。错误消息总是被记录下来。
	VModule        VModuleConfiguration `json:"vmodule,omitempty"` // VModule会覆盖单个文件的日志可见性k阈值。仅支持“文本”日志格式。
	Options        FormatOptions        `json:"options,omitempty"` // [Alpha]选项包含特定于不同日志格式的附加参数。只使用所选格式的选项，但所有选项都将得到验证。仅在启用LoggingAlphaOptions特性门时可用。
}

// FormatOptions contains options for the different logging formats.
type FormatOptions struct {
	// [Alpha] JSON contains options for logging format "json".
	// Only available when the LoggingAlphaOptions feature gate is enabled.
	JSON JSONOptions `json:"json,omitempty"`
}

// JSONOptions contains options for logging format "json".
type JSONOptions struct {
	// [Alpha] SplitStream redirects error messages to stderr while
	// info messages go to stdout, with buffering. The default is to write
	// both to stdout, without buffering. Only available when
	// the LoggingAlphaOptions feature gate is enabled.
	SplitStream bool `json:"splitStream,omitempty"`
	// [Alpha] InfoBufferSize sets the size of the info stream when
	// using split streams. The default is zero, which disables buffering.
	// Only available when the LoggingAlphaOptions feature gate is enabled.
	InfoBufferSize resource.QuantityValue `json:"infoBufferSize,omitempty"`
}

// VModuleConfiguration is a collection of individual file names or patterns
// and the corresponding verbosity threshold.
type VModuleConfiguration []VModuleItem

// VModuleItem defines verbosity for one or more files which match a certain
// glob pattern.
type VModuleItem struct {
	// FilePattern is a base file name (i.e. minus the ".go" suffix and
	// directory) or a "glob" pattern for such a name. It must not contain
	// comma and equal signs because those are separators for the
	// corresponding klog command line argument.
	FilePattern string `json:"filePattern"`
	// Verbosity is the threshold for log messages emitted inside files
	// that match the pattern.
	Verbosity VerbosityLevel `json:"verbosity"`
}

// VerbosityLevel 表示klog或logr 日志可见性k阈值。
type VerbosityLevel uint32
