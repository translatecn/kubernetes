package main

import (
	"fmt"
	"golang.org/x/time/rate"
)

func main() {

	li := rate.NewLimiter(rate.Limit(10), 100)

	fmt.Println(li.Reserve().Delay())
	fmt.Println(li.Reserve().Delay())
	fmt.Println(li.Reserve().Delay())
	fmt.Println(li.Reserve().Delay())
	fmt.Println(li.Reserve().Delay())
	fmt.Println(li.Reserve().Delay())
	fmt.Println(li.Reserve().Delay())
	fmt.Println(li.Reserve().Delay())
	fmt.Println(li.Reserve().Delay())
	fmt.Println(li.Reserve().Delay())
	fmt.Println(li.Reserve().Delay())
	fmt.Println(li.Reserve().Delay())
}
