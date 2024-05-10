package main

import (
	"fmt"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func main() {
	fldPath := field.NewPath("metadata")
	x := field.Invalid(fldPath.Child("generateName"), "pod-", "xxx")
	fmt.Println(x) // metadata.generateName: Invalid value: "pod-": xxx

}
