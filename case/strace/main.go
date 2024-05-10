package main

import (
	"k8s.io/utils/trace"
	"time"
)

func main() {
	doSomething()
}
func doSomething() {
	rootTrace := trace.New("rootOperation")
	defer rootTrace.LogIfLong(100 * time.Millisecond)

	func() {
		nestedTrace := rootTrace.Nest("nested", trace.Field{Key: "nestedFieldKey1", Value: "nestedFieldValue1"})
		defer nestedTrace.LogIfLong(50 * time.Millisecond)
		// do nested operation
		time.Sleep(time.Second)
	}()
}
