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

// Note: the example only works with the code within the same release/branch.
package main

import (
	"context"
	"flag"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"path/filepath"
)

func main() {
	var kubeconfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "company_config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)

	pod, err := clientset.CoreV1().Pods("default").Get(context.TODO(), "centos", metav1.GetOptions{})
	//kind := "Pod"
	//e := api.Event{
	//	TypeMeta: metav1.TypeMeta{
	//		Kind:       kind,
	//		APIVersion: pod.APIVersion,
	//	},
	//	ObjectMeta: metav1.ObjectMeta{
	//		Name:                       pod.Name + "." + string(uuid.NewUUID()),
	//		GenerateName:               pod.GenerateName,
	//		Namespace:                  pod.Namespace,
	//		UID:                        pod.UID,
	//		Generation:                 pod.Generation,
	//		CreationTimestamp:          pod.CreationTimestamp,
	//		DeletionTimestamp:          nil,
	//		DeletionGracePeriodSeconds: nil,
	//		Labels:                     pod.Labels,
	//		Annotations:                pod.Annotations,
	//		OwnerReferences:            pod.OwnerReferences,
	//	},
	//	InvolvedObject: api.ObjectReference{
	//		Kind:            kind,
	//		Namespace:       pod.Namespace,
	//		Name:            pod.Name,
	//		UID:             pod.UID,
	//		APIVersion:      pod.APIVersion,
	//		ResourceVersion: pod.ResourceVersion,
	//		FieldPath:       "spec.containers{centos}",
	//	},
	//	Reason:  "Evicted",
	//	Message: "Pod gpu usage exceeds the quota.",
	//	Source: api.EventSource{
	//		Component: "PLUGIN",
	//		Host:      "mac",
	//	},
	//	FirstTimestamp: metav1.Time{Time: time.Now()},
	//	LastTimestamp:  metav1.Time{Time: time.Now()},
	//	Count:          1,
	//	Type:           "Warning",
	//	EventTime:      metav1.MicroTime{},
	//	Series:         nil,
	//	Related:        nil,
	//}
	//fmt.Println(clientset.CoreV1().Events("default").Create(context.TODO(), &e, metav1.CreateOptions{}))
	pod.Status = v1.PodStatus{
		Phase:   "Failed",
		Message: "Pod gpu usage exceeds the quota.",
		Reason:  "Evicted",
	}
	clientset.CoreV1().Pods("default").UpdateStatus(context.Background(), pod, metav1.UpdateOptions{})
	clientset.CoreV1().Pods("default")
	//fmt.Println(clientset.CoreV1().Events("default").Update(context.TODO(), &e, metav1.UpdateOptions{}))
}
