 /*
Copyright 2014 The Kubernetes Authors.

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

package main

import (
	"os"

	"k8s.io/component-base/cli"
	_ "k8s.io/component-base/logs/json/register" // for JSON log format registration
	_ "k8s.io/component-base/metrics/prometheus/clientgo"
	_ "k8s.io/component-base/metrics/prometheus/version" // for version metric registration
	"k8s.io/kubernetes/cmd/kube-scheduler/app"
)

/*
	kube-scheduler 主要流程：
	1. 获取到未调度的podList
	2. 通过调度框架流程为pod选出一个适合的node(主要：过滤(去掉不符合的node)＋打分(取出评分最高的node))
	3. 提交给kube-apiserver
 */

func main() {
	// 启动scheduler入口
	command := app.NewSchedulerCommand()
	code := cli.Run(command)
	os.Exit(code)
}
