package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	f2()
}
func f2() {
	os.WriteFile("/tmp/a.txt", nil, os.ModePerm)
	exec.Command("/bin/bash", []string{"-c", "ln -s /tmp/a.txt /tmp/a.lnk"}...).Run().Error()
	fmt.Println(filepath.EvalSymlinks("/tmp/a.lnk"))
}
func f1() {
	fmt.Println(os.Lstat("/tmp/a.txt"))
	fmt.Println(os.Lstat("/tmp/a.lnk"))
	fmt.Println(os.Stat("/tmp/a.txt"))
	fmt.Println(os.Stat("/tmp/a.lnk"))
}
