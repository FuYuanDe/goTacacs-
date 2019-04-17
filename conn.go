//conn.go
package main

const (
	DefaultProtocol := "tcp"
	DefaultServerPort := 49
)

type conn struct {
	nc net.Conn

	ctx context.Context
	//接收报文, 给session提供 <-chan []byte 方法
	// recv chan []byte
	//回调函数
	cb func(data []byte)
	//发送报文
	send chan []byte
	sync.RWMutex
	//关闭通道
	done chan struct{}
}