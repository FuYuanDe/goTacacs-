//conn.go
package main

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
)

const (
	DefaultProtocol   = "tcp"
	DefaultServerPort = 49
)

type conn struct {
	sync.RWMutex
	nc net.Conn

	ctx context.Context
}

func (c *conn) connect(address addr) error {
	var lAddr string
	localPort := address.LocalPort
	if localPort == "" {
		localPort = DefaultLocalPort
	}

	if address.IpType == 6 {
		lAddr = net.JoinHostPort(network.GetInterfaceIP6Addr(address.LocalIf), localPort)
	} else {
		lAddr = net.JoinHostPort(network.GetInterfaceIP4Addr(address.LocalIf), localPort)
	}
	dialer := net.Dialer{}

	addr, err := net.ResolveTCPAddr("tcp", lAddr)
	if err != nil {
		return err
	}

	dialer.LocalAddr = addr
	// var idle time.Duration
	// if address.IdleTime == 0 {
	// 	idle = DefaultIdleTime
	// } else {
	// 	idle = time.Duration(address.IdleTime) * time.Second
	// }
	// dialer.Timeout = idle

	serverPort := address.ServerPort
	if serverPort == "" {
		serverPort = DefaultServerPort
	}

	nc, err := dialer.DialContext(c.ctx, "tcp", net.JoinHostPort(address.ServerIp, serverPort))
	if err != nil {
		fmt.Printf("Create tcp connection %s : %s fail:%s", address.ServerIp, serverPort, err.Error())
		return err
	}
	c.nc = nc

	//创建连接的是否使用三个gorouting去循环处理报文事件
	go c.dispatch()
	go c.writeLoop()
	go c.readLoop()

	return nil
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

	if config.ServerPort == 0 {
		return errors.New("invalid server port")
	}
	serverPort := address.ServerPort
	if serverPort == "" {
		serverPort = DefaultServerPort
	}

	nc, err := dialer.DialContext(c.ctx, "tcp", net.JoinHostPort(address.ServerIp, serverPort))
	if err != nil {
		fmt.Printf("Create tcp connection %s : %s fail:%s", address.ServerIp, serverPort, err.Error())
		return err
	}
	c.nc = nc

	//创建连接的是否使用三个gorouting去循环处理报文事件
	go c.dispatch()
	go c.writeLoop()
	go c.readLoop()

	return nil
}

func newConn(ctx context.Context, config TacacsConfig) (*conn, error) {
	c := &conn{}
	c.ctx = ctx
}

func newConn(ctx context.Context, address addr, cb func([]byte)) (*conn, error) {
	c := &conn{}
	c.cb = cb
	c.send = make(chan []byte, 100)
	c.done = make(chan struct{})
	c.ctx = ctx

	err := c.connect(address)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (c *conn) close() {
	c.Lock()

	if c.send != nil {
		close(c.send)
		c.send = nil
	}

	if c.done != nil {
		close(c.done)
		c.done = nil
	}

	if c.nc != nil {
		c.nc.Close()
		c.nc = nil
	}

	c.Unlock()
}
