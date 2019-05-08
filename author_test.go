// session_test
package tacacs

import (
	"fmt"
	"testing"
)

func TestAuthor(t *testing.T) {
	var config TacacsConfig
	config.ConnMultiplexing = false
	config.LocalIP = ""
	config.IPtype = "ip4"
	config.ServerIP = "172.25.77.192"
	config.ServerPort = 49
	config.ShareKey = "12345678"

	TacacsInit()
	TacacsConfigSet(config)
	sess, err := NewSession(TacacsMng.ctx, 100, "huangjinxin", "huangjinxin")
	if err != nil {
		fmt.Printf("Author fail due to NewSession failure")
	}
	err = Author(sess, AuthenMethodNotSet, PrivLvlRoot, AuthenTypeNotSet, AuthenServiceNone, "service=shell", "cmd=enable")

	if err != nil {
		fmt.Println("Author fail, error msg :" + err.Error())
	} else {
		fmt.Printf("Author success\n")
	}
	TacacsExit()
}
