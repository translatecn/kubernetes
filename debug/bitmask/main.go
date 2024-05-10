package main

import (
	"fmt"
	"k8s.io/kubernetes/pkg/kubelet/cm/topologymanager/bitmask"
)

func IterateBitMasks(bits []int) {
	var iterate func(bits, accum []int, size int)
	iterate = func(bits, accum []int, size int) {
		if len(accum) == size {
			fmt.Println(accum)
			return
		}
		for i := range bits {
			iterate(bits[i+1:], append(accum, bits[i]), size)
		}
	}

	for i := 1; i <= len(bits); i++ {
		iterate(bits, []int{}, i)
	}
}

func main3() {
	IterateBitMasks([]int{0, 1, 2, 3, 4})
}

func main2() {
	defaultAffinity, _ := bitmask.NewBitMask([]int{0, 1, 2, 3, 4, 5, 6, 7}...)
	a2, _ := bitmask.NewBitMask([]int{}...)
	a2.Add(2)
	fmt.Println(defaultAffinity)
	fmt.Println(a2)
	mergedAffinity := bitmask.And(defaultAffinity, a2)
	fmt.Println(mergedAffinity)
}

type TopologyHint struct {
	Name  string
	Value int
}

// 迭代所有提供程序拓扑提示
func iterateAllProviderTopologyHints(allProviderHints [][]TopologyHint, callback func([]TopologyHint)) {
	// Internal helper function to accumulate the permutation before calling the callback.
	var iterate func(i int, accum []TopologyHint)
	iterate = func(i int, accum []TopologyHint) {
		// Base case: we have looped through all providers and have a full permutation.
		if i == len(allProviderHints) {
			callback(accum)
			return
		}

		// Loop through all hints for provider 'i', and recurse to build the
		// permutation of this hint with all hints from providers 'i++'.
		for j := range allProviderHints[i] {
			iterate(i+1, append(accum, allProviderHints[i][j]))
		}
	}
	iterate(0, []TopologyHint{})
}

func main() {
	iterateAllProviderTopologyHints([][]TopologyHint{
		{
			{
				Name:  "cpu",
				Value: 0,
			}, {
				Name:  "cpu",
				Value: 1,
			},
			{
				Name:  "cpu",
				Value: 2,
			},
			{
				Name:  "cpu",
				Value: 3,
			},
		},
		{
			{
				Name:  "mem",
				Value: 0,
			}, {
				Name:  "mem",
				Value: 1,
			},
			{
				Name:  "mem",
				Value: 2,
			},
			{
				Name:  "mem",
				Value: 3,
			},
		},
		{
			{
				Name:  "gpu",
				Value: 0,
			}, {
				Name:  "gpu",
				Value: 1,
			},
			{
				Name:  "gpu",
				Value: 2,
			},
			{
				Name:  "gpu",
				Value: 3,
			},
		},
	}, func(hints []TopologyHint) {
		fmt.Println(hints)
	})

}
