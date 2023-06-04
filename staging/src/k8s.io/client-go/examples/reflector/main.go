package main

import (
	"context"
	"fmt"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"path/filepath"
	"time"
)

func main() {
	namespace := "kube-system"
	cfg, _ := clientcmd.BuildConfigFromFlags("", filepath.Join(homedir.HomeDir(), ".kube", "config"))

	kubeClient, _ := kubernetes.NewForConfig(cfg)

	listFunc := func(opts metav1.ListOptions) (runtime.Object, error) {
		return kubeClient.CoreV1().Pods(namespace).List(context.TODO(), opts)
	}
	watchFunc := func(opts metav1.ListOptions) (watch.Interface, error) {
		return kubeClient.CoreV1().Pods(namespace).Watch(context.TODO(), opts)
	}

	store := cache.NewStore(cache.MetaNamespaceKeyFunc)
	exceptType := corev1.Resource("pod")
	reflector := cache.NewNamedReflector(
		"object",
		&cache.ListWatch{ListFunc: listFunc, WatchFunc: watchFunc},
		exceptType,
		store,
		0,
	)

	go reflector.Run(make(<-chan struct{}))

	for {
		time.Sleep(time.Second * 5)
		fmt.Println(store.List())
	}
}
