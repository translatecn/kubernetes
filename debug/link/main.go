package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println(os.Lstat("/tmp/a.txt"))
	fmt.Println(os.Lstat("/tmp/a.lnk"))
	fmt.Println(os.Stat("/tmp/a.txt"))
	fmt.Println(os.Stat("/tmp/a.lnk"))
}
