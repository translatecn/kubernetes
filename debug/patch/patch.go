package main

import (
	"encoding/json"
	"fmt"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
)

func main() {
	var s int64 = 123
	oldData, _ := json.Marshal(corev1.Pod{
		Spec: corev1.PodSpec{
			NodeName: "a",
		},
	})
	newData, _ := json.Marshal(corev1.Pod{
		Spec: corev1.PodSpec{
			NodeName:              "b",
			ActiveDeadlineSeconds: &s,
		},
	})
	patch, _ := strategicpatch.CreateTwoWayMergePatch(oldData, newData, corev1.Pod{})
	fmt.Println(string(patch))
}
