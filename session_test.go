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
	config.ServerIP = "172.25.1.192"
	config.ServerPort = 49

	TacacsInit()
	TacacsConfigSet(config)

	err := AuthenASCII("tina", "12345678")
	if err != nil {
		fmt.Println("authen fail, error msg :" + err.Error())
	} else {
		fmt.Printf("authen ascii success")
	}
}
