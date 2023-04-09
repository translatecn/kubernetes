package main

import "k8s.io/apiserver/pkg/authentication/token/tokenfile"

func main() {
	tokenfile.NewCSV("./debug/csv/a.csv")
}
