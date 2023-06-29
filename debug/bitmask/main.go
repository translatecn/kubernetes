package main

import "fmt"

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

func main() {
	IterateBitMasks([]int{0, 1, 2, 3, 4})
}
