// session_test
package tacacs

import (
	"fmt"
	"testing"
	"time"
)

func TestConn(t *testing.T) {
	var config TacacsConfig
	config.ConnMultiplexing = false
	config.LocalIP = ""
	//config.LocalPort = 3600
	config.IPtype = "ip4"
	config.ServerIP = "134.175.140.177"
	//config.ServerIP = "172.25.1.192"
	config.ServerPort = 49
	config.ShareKey = "12345678"

	TacacsInit()
	TacacsConfigSet(config)
	sess, err := NewSession(TacacsMng.ctx, 100, "username", "password")
	if err != nil {
		fmt.Printf("newSession fail\n")
		return
	} else {
		fmt.Printf("NewSession success,id:%d\n", sess.SessionID)
	}
	time.Sleep(1000 * time.Second)
}

func TestTacacsInit(t *testing.T) {
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

func TestMultiSession(t *testing.T) {
	var config TacacsConfig
	config.ConnMultiplexing = true
	config.LocalIP = ""
	config.IPtype = "ip4"
	config.ServerIP = "134.175.140.177"
	//config.ServerIP = "134.175.140.178"
	//config.ServerIP = "172.25.77.192"
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
	//config.ServerIP = "134.175.140.177"
	//config.ServerIP = "134.175.140.178"
	config.ServerIP = "172.25.77.192"
	config.ServerPort = 49
	config.ShareKey = "12345678"

	TacacsInit()
	TacacsConfigSet(config)

	err := AuthenPAP(10, "mason", "0000")
	if err != nil {
		fmt.Println("AuthenPAP fail, error msg :" + err.Error())
	} else {
		fmt.Printf("AuthenPAP success\n")
	}
	TacacsExit()
}

func TestAuthor(t *testing.T) {
	var config TacacsConfig
	config.ConnMultiplexing = false
	config.LocalIP = ""
	config.IPtype = "ip4"
	//config.ServerIP = "134.175.140.177"
	config.ServerIP = "172.25.77.192"
	config.ServerPort = 49
	config.ShareKey = "12345678"

	TacacsInit()
	TacacsConfigSet(config)
	sess, err := NewSession(TacacsMng.ctx, 100, "mason", "0000")
	if err != nil {
		fmt.Printf("Author fail due to NewSession failure")
	}
	err = Author(sess, TacacsAuthenMethodNotSet, TacacsPrivLvlRoot, TacacsAuthenTypeNotSet, TacacsAuthenServiceNone, "service=shell", "cmd=ls")

	if err != nil {
		fmt.Println("Author fail, error msg :" + err.Error())
	} else {
		fmt.Printf("Author success\n")
	}
	TacacsExit()
}
