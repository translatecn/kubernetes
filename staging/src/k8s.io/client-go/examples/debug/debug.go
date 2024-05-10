package main

import (
	"fmt"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	cfg, _ := clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
	clientset.NewForConfig(cfg)
	fmt.Println(scheme.Scheme.VersionsForGroupKind(schema.GroupKind{
		Group: "",
		Kind:  "Pod",
	}))
}
