package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

func main() {
	http.HandleFunc("/name", func(w http.ResponseWriter, r *http.Request) {
		flusher := w.(http.Flusher)
		for i := 0; i < 10; i++ {
			fmt.Fprintf(w, "Hello\n")
			flusher.Flush() // 响应头会添加一个  Transfer-Encoding:chunked
			<-time.Tick(time.Second)
		}
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// curl http://127.0.0.1:8080/name

// kubectl proxy --port=8011

// curl localhost:8011/api/v1/watch/namespaces/kube-system/configmaps/coredns

//
