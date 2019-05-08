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
