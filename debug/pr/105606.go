package main

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"
)

func main() {

	go func() {
		for j := 0; j < 100000000; j++ {
			time.Sleep(time.Millisecond)
			go func() {
				workersNumber := 16
				items := make([]int, 100, 100)
				wg := sync.WaitGroup{}
				toProcess := make(chan int, 2*workersNumber)
				errs := make(chan error, workersNumber+1)

				go func() {
					for i := 0; i < len(items); i++ {
						toProcess <- i // 内存泄漏
					}
					close(toProcess)
				}()

				wg.Add(workersNumber)
				for i := 0; i < workersNumber; i++ {
					go func() {
						// panics don't cross goroutine boundaries
						defer wg.Done()

						for _ = range toProcess {
							errs <- errors.New("index")
							return
						}
					}()
				}
				wg.Wait()
			}()
		}
	}()
	for {
		time.Sleep(time.Second)
		fmt.Println(runtime.NumGoroutine())
	}
}
