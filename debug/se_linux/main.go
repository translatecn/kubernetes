package main

import (
	"fmt"
	"github.com/opencontainers/selinux/go-selinux"
	"github.com/opencontainers/selinux/go-selinux/label"
)

func main() {
	fmt.Println(selinux.GetEnabled())
	args := []string{
		"user:1",
		"role:user2_role",
		"type:x",
		"level:s0:c123,c456",
	}
	processLabel, fileLabel, err := label.InitLabels(args)
	fmt.Println(processLabel)
	fmt.Println(fileLabel)
	fmt.Println(err)
}
