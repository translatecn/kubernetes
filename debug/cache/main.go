package main

import (
	"flag"
	"fmt"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"k8s.io/klog/v2"
	"path/filepath"
	"time"
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
	clientConfig, err := clientcmd.BuildConfigFromFlags(master, kubeconfig)
	if err != nil {
		klog.Fatal(err)
	}

	//
	//clientConfig, _ := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
	//	&clientcmd.ClientConfigLoadingRules{ExplicitPath: s.KubeConfig},
	//	&clientcmd.ConfigOverrides{},
	//).ClientConfig()

	c, _ := clientset.NewForConfig(clientConfig)
	if err != nil {
		klog.Fatal(err)
	}

	lw := cache.NewListWatchFromClient(c.CoreV1().RESTClient(), "pods", metav1.NamespaceAll, fields.Everything())
	//lw := cache.NewListWatchFromClient(c.CoreV1().RESTClient(), "pods", metav1.NamespaceAll, fields.OneTermEqualSelector("spec.nodeName", string("nodeName")))
	r := cache.NewReflector(lw, &v1.Pod{}, cache.NewUndeltaStore(send, cache.MetaNamespaceKeyFunc), 0)
	go r.Run(wait.NeverStop)
	<-time.After(time.Hour)
}

func send(items []interface{}) { // 当前全量的数据
	for _, item := range items {
		v, ok := item.(*v1.Pod)
		if ok {
			fmt.Println(v.Name)
		}
	}

}
