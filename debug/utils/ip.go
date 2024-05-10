package utils

import (
	"net"
	"strings"
)

func GetOutBoundIP() (ip string) {
	conn, _ := net.Dial("udp", "8.8.8.8:53")

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	ip = strings.Split(localAddr.String(), ":")[0]
	return
}
