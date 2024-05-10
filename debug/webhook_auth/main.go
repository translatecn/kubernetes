package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/golang/glog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

var port string

func main() {
	flag.StringVar(&port, "port", "9999", "http server port")
	flag.Parse()
	// 启动httpserver
	wbsrv := WebHookServer{server: &http.Server{
		Addr: fmt.Sprintf(":%v", port),
	}}
	mux := http.NewServeMux()
	mux.HandleFunc("/auth", wbsrv.serve)
	wbsrv.server.Handler = mux

	// 启动协程来处理
	go func() {
		if err := wbsrv.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			glog.Errorf("Failed to listen and serve webhook server: %v", err)
		}
	}()

	glog.Info("Server started")

	// 优雅退出
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan

	glog.Infof("Got OS shutdown signal, shutting down webhook server gracefully...")
	_ = wbsrv.server.Shutdown(context.Background())
}
