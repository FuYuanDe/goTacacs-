//conn.go
package tacacs

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	//	"time"
)

type conn struct {
	sync.RWMutex
	nc net.Conn

	ctx context.Context
}

func (c *conn) connect(config TacacsConfig) error {
	dialer := net.Dialer{}
	if config.LocalPort != 0 {
		LocalAddr := net.JoinHostPort(config.LocalIP, strconv.FormatUint(uint64(config.LocalPort), 10))
		addr, err := net.ResolveTCPAddr("tcp", LocalAddr)
		if err != nil {
			return err
		}

		dialer.LocalAddr = addr
	}

	// var idle time.Duration
	// if address.IdleTime == 0 {
	// 	idle = DefaultIdleTime
	// } else {
	// 	idle = time.Duration(address.IdleTime) * time.Second
	// }
	// dialer.Timeout = idle

	//var keepAlive time.Duration
	//keepAlive = time.Second * 3
	//dialer.KeepAlive = keepAlive

	if config.ServerPort == 0 {
		return errors.New("invalid server port")
	}

	nc, err := dialer.DialContext(c.ctx, "tcp", net.JoinHostPort(config.ServerIP, strconv.FormatUint(uint64(config.ServerPort), 10)))
	if err != nil {
		fmt.Printf("Create tcp connection %s : %s fail:%s", config.ServerIP, config.ServerPort, err.Error())
		return err
	}

	c.nc = nc

	return nil
}

func newConn(ctx context.Context, config TacacsConfig) (*conn, error) {
	c := &conn{}
	c.ctx = ctx

	err := c.connect(config)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (c *conn) close() {
	c.Lock()

	if c.nc != nil {
		c.nc.Close()
		c.nc = nil
	}

	c.Unlock()
}
