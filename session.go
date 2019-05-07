// session.go
package tacacs

import (
	"context"
	"errors"
	//"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"
)

type TacacsConfig struct {
	IPtype           string //"ip4","ip6"
	ServerIP         string
	ServerPort       uint16
	LocalIP          string
	LocalPort        uint16
	ConnMultiplexing bool
	ShareKey         string
}

func TacacsConfigSet(config TacacsConfig) {
	TacacsMng.Lock()
	defer TacacsMng.Unlock()
	TacacsMng.Config = config
}

func TacacsConfigGet() (config TacacsConfig) {
	TacacsMng.Lock()
	defer TacacsMng.Unlock()
	return TacacsMng.Config

}

const (
	MaxUint8 = ^uint8(0)
)

type Manager struct {
	Sessions sync.Map

	Trans  *Transport
	ctx    context.Context
	cancel context.CancelFunc
	sync.RWMutex

	ServerConnMultiplexing bool
	Config                 TacacsConfig
}

type Session struct {
	sync.Mutex
	timeout      int
	SessionSeqNo uint8
	SessionID    uint32
	UserName     string
	Password     string
	ReadBuffer   chan []byte
	mng          *Manager
	t            *Transport
	ctx          context.Context
	restart      bool
}

func NewSession(ctx context.Context, timeout int, name, passwd string) (*Session, error) {
	if TacacsMng == nil {
		return nil, errors.New("tacacs not init")
	}
	sess := &Session{}
	sess.Password = passwd
	sess.UserName = name
	if timeout == 0 {
		sess.timeout = (1<<31 - 1)
	} else {
		sess.timeout = timeout
	}

	sess.SessionSeqNo = 1
	sess.ReadBuffer = make(chan []byte, 10)
	sess.mng = TacacsMng
	sess.ctx = ctx
	rand.Seed(time.Now().Unix())
	SessionID := rand.Uint32()
	for {
		if _, ok := TacacsMng.Sessions.Load(SessionID); ok {
			SessionID = rand.Uint32()
		} else {
			break
		}
	}
	fmt.Printf("sessionID :%d\n", SessionID)
	sess.SessionID = SessionID

	sess.mng.Lock()
	if sess.mng.ServerConnMultiplexing {
		if sess.mng.Trans == nil {
			sess.t = sess.mng.Trans
			fmt.Println("reuse transport")
		}
	}
	sess.mng.Unlock()

	if sess.t == nil {
		childCtx, _ := context.WithTimeout(ctx, time.Duration(sess.timeout)*time.Second)
		t, err := newTransport(childCtx, TacacsMng.Config)
		if err != nil {
			fmt.Printf("create new transport fail,%s\n", err.Error())
			return nil, err
		} else {
			sess.t = t
			sess.mng.Lock()
			if sess.mng.Trans == nil {
				sess.mng.Trans = t
			}
			sess.mng.Unlock()
		}
	}

	TacacsMng.Sessions.Store(SessionID, sess)
	return sess, nil
}

func SessionDelete(key, value interface{}) bool {
	sess, ok := value.(*Session)
	if ok {
		sess.close()
	} else {
		fmt.Printf("*** error, interface assert fail ***\n")
	}
	return true
}

var TacacsMng *Manager

func TacacsInit() {
	if TacacsMng == nil {
		TacacsMng = &Manager{}
		TacacsMng.ctx, TacacsMng.cancel = context.WithCancel(context.Background())
		fmt.Printf("--> tacacs init success\n")
	} else {
		fmt.Printf("--> tacacs already init\n")
	}
}

func TacacsExit() {
	if TacacsMng == nil {
		fmt.Println("error, tacacs not init, exit fail")
	} else {
		fmt.Println("close session....")
		TacacsMng.Sessions.Range(SessionDelete)
		TacacsMng.Lock()
		if TacacsMng.Trans != nil {
			TacacsMng.Trans.close()
		}
		TacacsMng.Unlock()
		fmt.Printf("TACACS exit success\n")
	}
}

func (sess *Session) close() {
	sess.mng.Sessions.Delete(sess.SessionID)
	sess.mng.Lock()
	if !sess.mng.ServerConnMultiplexing {
		if sess.mng.Trans == sess.t {
			sess.t.close()
			sess.mng.Trans = nil
		}
	}
	sess.mng.Unlock()
	fmt.Println("session close success")
}
