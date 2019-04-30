// session_test
package main

import (
	"fmt"
	"testing"
)

func TestTacacsInit(t *testing.T) {
	var config TacacsConfig
	config.ConnMultiplexing = false
	config.LocalIP = ""
	//config.LocalPort = 3600
	config.IPtype = "ip4"
	//config.ServerIP = "134.175.140.177"
	config.ServerIP = "172.25.1.192"
	config.ServerPort = 49
	config.ShareKey = "12345678"

	TacacsInit()
	TacacsConfigSet(config)

	err := AuthenASCII("mason", "0000")
	if err != nil {
		fmt.Println("authen fail, error msg :" + err.Error())
	} else {
		fmt.Printf("authen ascii success")
	}
}
