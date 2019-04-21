// main.go
package main

import (
	"fmt"
)

type TacacsConfig struct {
	IPtype     string //"ip4","ip6"
	ServerIP   string
	ServerPort uint16
	LocalIP    string
	LocalPort  uint16
	SingleConn bool //
}

var DefaultConfig = &TacacsConfig{
	"ip4",
	"192.168.199.213",
	49,
	"",
	4500, true}

func main() {
	fmt.Printf("iptype:%s,ServerIP:%s:%d,LocalIP:%s:%d",
		DefaultConfig.IPtype,
		DefaultConfig.ServerIP, DefaultConfig.ServerPort,
		DefaultConfig.LocalIP, DefaultConfig.LocalPort)
}
