package main

import (
	"context"
	"flag"
	"fmt"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"k8s.io/klog/v2"
	"path/filepath"
)

func main() {
	var kubeconfig string
	var master string
	if home := homedir.HomeDir(); home != "" {
		flag.StringVar(&kubeconfig, "kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		flag.StringVar(&kubeconfig, "kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.StringVar(&master, "master", "", "master url")
	flag.Parse()
	// creates the connection
	config, err := clientcmd.BuildConfigFromFlags(master, kubeconfig)
	if err != nil {
		klog.Fatal(err)
	}

	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		klog.Fatal(err)
	}
	options := metav1.ListOptions{
		TypeMeta:             metav1.TypeMeta{},
		LabelSelector:        "",
		FieldSelector:        "",
		Watch:                false,
		AllowWatchBookmarks:  false,
		ResourceVersion:      "",
		ResourceVersionMatch: "",
		TimeoutSeconds:       nil,
		Limit:                2,
		Continue:             "",
	}
	obj, _ := clientset.CoreV1().RESTClient().Get(). // 其实就是RESTClient.Get(）,返回的是*rest.Request对象
								Namespace("").
								Resource("pods").
								VersionedParams(&options, metav1.ParameterCodec).
								Do(context.TODO()).
								Get()
	m, _ := meta.ListAccessor(obj)
	fmt.Println(len(m.(*v1.PodList).Items))
}
