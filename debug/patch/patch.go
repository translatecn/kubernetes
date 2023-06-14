package main

import (
	"encoding/json"
	"fmt"
	"github.com/nsf/jsondiff"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"reflect"
	"strings"
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

	// ------------------
	//o1 := make(map[string]interface{})
	//o2 := make(map[string]interface{})
	//json.Unmarshal(oldData, &o1)
	//json.Unmarshal(newData, &o2)
	//d := new(JsonDiff)
	//
	//fmt.Println(string(oldData))
	//fmt.Println(string(newData))
	//jsonDiffDict(o1, o2, 3, d)
	//fmt.Println(d.Result)

	// ------------------
	//result, _ := jsondiff.CompareStreams(bytes.NewReader(oldData), bytes.NewReader(newData), &opts)
	opts := jsondiff.DefaultConsoleOptions()
	opts.Added = jsondiff.Tag{}
	opts.Removed = jsondiff.Tag{}
	opts.Changed = jsondiff.Tag{}
	opts.Skipped = jsondiff.Tag{}
	//opts.SkippedObjectProperty = func(n int) string { return fmt.Sprintf("[skipped keys:%d]", n) }
	//opts.SkippedArrayElement = func(n int) string { return fmt.Sprintf("[skipped elements:%d]", n) }
	opts.Indent = "    "
	opts.SkipMatches = true
	opts.SkippedObjectProperty = nil
	opts.SkippedArrayElement = nil
	_, diff := jsondiff.Compare(oldData, newData, &opts)
	fmt.Println(diff)
}

type JsonDiff struct {
	HasDiff bool
	Result  string
}

func jsonDiffDict(json1, json2 map[string]interface{}, depth int, diff *JsonDiff) {
	blank := strings.Repeat(" ", 2*(depth-1))
	longBlank := strings.Repeat(" ", 2*(depth))
	diff.Result = diff.Result + "\n" + blank + "{"
	for key, value := range json1 {
		quotedKey := fmt.Sprintf("\"%s\"", key)
		if _, ok := json2[key]; ok {
			switch value.(type) {
			case map[string]interface{}:
				if _, ok2 := json2[key].(map[string]interface{}); !ok2 {
					diff.HasDiff = true
					diff.Result = diff.Result + "\n-" + blank + quotedKey + ": " + marshal(value) + ","
					diff.Result = diff.Result + "\n+" + blank + quotedKey + ": " + marshal(json2[key])
				} else {
					diff.Result = diff.Result + "\n" + longBlank + quotedKey + ": "
					jsonDiffDict(value.(map[string]interface{}), json2[key].(map[string]interface{}), depth+1, diff)
				}
			case []interface{}:
				diff.Result = diff.Result + "\n" + longBlank + quotedKey + ": "
				if _, ok2 := json2[key].([]interface{}); !ok2 {
					diff.HasDiff = true
					diff.Result = diff.Result + "\n-" + blank + quotedKey + ": " + marshal(value) + ","
					diff.Result = diff.Result + "\n+" + blank + quotedKey + ": " + marshal(json2[key])
				} else {
					jsonDiffList(value.([]interface{}), json2[key].([]interface{}), depth+1, diff)
				}
			default:
				if !reflect.DeepEqual(value, json2[key]) {
					diff.HasDiff = true
					diff.Result = diff.Result + "\n-" + blank + quotedKey + ": " + marshal(value) + ","
					diff.Result = diff.Result + "\n+" + blank + quotedKey + ": " + marshal(json2[key])
				} else {
					diff.Result = diff.Result + "\n" + longBlank + quotedKey + ": " + marshal(value)
				}
			}
		} else {
			diff.HasDiff = true
			diff.Result = diff.Result + "\n-" + blank + quotedKey + ": " + marshal(value)
		}
		diff.Result = diff.Result + ","
	}
	for key, value := range json2 {
		if _, ok := json1[key]; !ok {
			diff.HasDiff = true
			diff.Result = diff.Result + "\n+" + blank + "\"" + key + "\"" + ": " + marshal(value) + ","
		}
	}
	diff.Result = diff.Result + "\n" + blank + "}"
}

func jsonDiffList(json1, json2 []interface{}, depth int, diff *JsonDiff) {
	blank := strings.Repeat(" ", 2*(depth-1))
	longBlank := strings.Repeat(" ", 2*(depth))
	diff.Result = diff.Result + "\n" + blank + "["
	size := len(json1)
	if size > len(json2) {
		size = len(json2)
	}
	for i := 0; i < size; i++ {
		switch json1[i].(type) {
		case map[string]interface{}:
			if _, ok := json2[i].(map[string]interface{}); ok {
				jsonDiffDict(json1[i].(map[string]interface{}), json2[i].(map[string]interface{}), depth+1, diff)
			} else {
				diff.HasDiff = true
				diff.Result = diff.Result + "\n-" + blank + marshal(json1[i]) + ","
				diff.Result = diff.Result + "\n+" + blank + marshal(json2[i])
			}
		case []interface{}:
			if _, ok2 := json2[i].([]interface{}); !ok2 {
				diff.HasDiff = true
				diff.Result = diff.Result + "\n-" + blank + marshal(json1[i]) + ","
				diff.Result = diff.Result + "\n+" + blank + marshal(json2[i])
			} else {
				jsonDiffList(json1[i].([]interface{}), json2[i].([]interface{}), depth+1, diff)
			}
		default:
			if !reflect.DeepEqual(json1[i], json2[i]) {
				diff.HasDiff = true
				diff.Result = diff.Result + "\n-" + blank + marshal(json1[i]) + ","
				diff.Result = diff.Result + "\n+" + blank + marshal(json2[i])
			} else {
				diff.Result = diff.Result + "\n" + longBlank + marshal(json1[i])
			}
		}
		diff.Result = diff.Result + ","
	}
	for i := size; i < len(json1); i++ {
		diff.HasDiff = true
		diff.Result = diff.Result + "\n-" + blank + marshal(json1[i])
		diff.Result = diff.Result + ","
	}
	for i := size; i < len(json2); i++ {
		diff.HasDiff = true
		diff.Result = diff.Result + "\n+" + blank + marshal(json2[i])
		diff.Result = diff.Result + ","
	}
	diff.Result = diff.Result + "\n" + blank + "]"
}
func marshal(j interface{}) string {
	value, _ := json.Marshal(j)
	return string(value)
}
