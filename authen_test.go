// session_test
package tacacs

import (
	"fmt"
	"testing"
	"time"
)

func TestSingleConn(t *testing.T) {
	var config TacacsConfig
	config.ConnMultiplexing = true
	config.LocalIP = ""
	config.IPtype = "ip4"
	config.ServerIP = "134.175.140.177"
	config.ServerPort = 49
	config.ShareKey = "12345678"

	TacacsInit()
	TacacsConfigSet(config)

	err := AuthenASCII(10, "mason", "0000")
	if err != nil {
		fmt.Println("authen fail, error msg :" + err.Error())
	} else {
		fmt.Println("authen ascii success")
	}

	err = AuthenASCII(10, "mason", "0000")
	if err != nil {
		fmt.Println("authen fail, error msg :" + err.Error())
	} else {
		fmt.Println("authen ascii success")
	}

	/*
		go func() {
			for i := 0; i < 5; i++ {
				err := AuthenASCII(10, "mason", "0000")
				if err != nil {
					fmt.Println("authen fail, error msg :" + err.Error())
				} else {
					fmt.Println("authen ascii success")
				}
			}
		}()
	*/
	time.Sleep(100 * time.Second)
	TacacsExit()
}

func TestAuthenPAP(t *testing.T) {
	var config TacacsConfig
	config.ConnMultiplexing = false
	config.LocalIP = ""
	//config.LocalPort = 3600
	config.IPtype = "ip4"
	config.ServerIP = "172.25.77.192"
	config.ServerPort = 49
	config.ShareKey = "12345678"

	TacacsInit()
	TacacsConfigSet(config)

	err := AuthenPAP(10, "dddd", "0000")
	if err != nil {
		fmt.Println("AuthenPAP fail, error msg :" + err.Error())
	} else {
		fmt.Printf("AuthenPAP success\n")
	}
	TacacsExit()
}

func TestAuthenASCII(t *testing.T) {
	var config TacacsConfig
	config.ConnMultiplexing = false
	config.LocalIP = ""
	//config.LocalPort = 3600
	config.IPtype = "ip4"
	config.ServerIP = "134.175.140.177"
	//config.ServerIP = "134.175.140.178"
	//config.ServerIP = "172.25.1.192"
	config.ServerPort = 49
	config.ShareKey = "12345678"

	TacacsInit()
	TacacsConfigSet(config)

	err := AuthenASCII(10, "mason", "0000")
	if err != nil {
		fmt.Println("authen fail, error msg :" + err.Error())
	} else {
		fmt.Printf("authen ascii success")
	}
	TacacsExit()
}
