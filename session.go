// session.go
package main

import (
	"context"
	"math/rand"
	"sync"
)

type TacacsConfig struct {
	IPtype           string //"ip4","ip6"
	ServerIP         string
	ServerPort       uint16
	LocalIP          string
	LocalPort        uint16
	ConnMultiplexing bool
}

func ConfigSet(config TacacsCOnfig) {
	TacacsMng.Lock()
	defer TacacsMng.Unlock()
	TacacsMng.Config = config
}

func ConfigGet() (config TacacsCOnfig) {
	TacacsMng.Lock()
	defer TacacsMng.Unlock()
	config := TacacsMng.Config
	return config
}

const (
	MaxUint8 = ^uint8(0)
)

type Config struct {
}

type Manager struct {
	Sessions         sync.Map
	ConnMultiplexing bool

	Trans *Transport
	ctx   context.Context
	sync.RWMutex
	Config TacacsConfig
}

type Session struct {
	sync.Mutex
	SessionSeqNo uint8
	SessionID    uint32
	UserName     string
	Password     string
}

func NewSession(name, passwd string) {
	sess := &Session{}
	sess.Password = passwd
	sess.UserName = name
	sess.SessionSeqNo = 1
	rand.Seed(time.Now().Unix())
	SessionID := rand.Uint32()
	for {
		if _, ok := TacacsMng.Sessions.Load(SessionID); ok {
			SessionID = rand.Uint32()
		} else {
			break
		}
	}
	sess.SessionID = SessionID
	TacacsMng.Sessions.Store(SessionID, &sess)

}

var TacacsMng *Manager

func TacacsInit() {
	TacacsMng = &Manager{}
	TacacsMng.ctx = context.TODO()
}
