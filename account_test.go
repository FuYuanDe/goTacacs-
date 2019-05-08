// session_test
package tacacs

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAccount(t *testing.T) {
	var config TacacsConfig
	config.ConnMultiplexing = false
	config.LocalIP = ""
	config.IPtype = "ip4"
	config.ServerIP = "172.25.77.192"
	config.ServerPort = 49
	config.ShareKey = "12345678"

	var account AccountConfig
	account.Flags = AcctFlagStart
	account.AuthenMethod = AuthenMethodTACACSPLUS
	account.PrivLvl = PrivLvlRoot
	account.AuthenType = AuthenTypeNotSet
	account.AuthenService = AuthenServiceNone

	TacacsInit()
	TacacsConfigSet(config)
	sess, err := NewSession(TacacsMng.ctx, 100, "huangjinxin", "huangjinxin")
	if err != nil {
		fmt.Printf("Account fail due to NewSession failure")
	}
	now := time.Now()
	secs := now.Unix()
	startTime := make([]string, 2)
	startTime[0] = "start_time="
	time := strings.Join(startTime, strconv.FormatInt(secs, 10))
	err = Account(sess, account, "task_id=100", time)

	if err != nil {
		fmt.Println("Account fail, error msg :" + err.Error())
	} else {
		fmt.Printf("Account success\n")
	}
	TacacsExit()
}
