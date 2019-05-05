// transport.go
package tacacs

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
)

type Transport struct {
	netConn *conn
	sendChn chan []byte
}

func newTransport(ctx context.Context, config TacacsConfig) (*Transport, error) {
	t := &Transport{}
	var err error
	t.netConn, err = newConn(ctx, config)
	if err != nil {
		return nil, err
	} else {
		fmt.Println("create conn success")
	}

	t.sendChn = make(chan []byte, 100)
	go t.readLoop()
	go t.writeLoop()

	return t, nil

}

func (t *Transport) close() {
	t.netConn.Lock()
	if t.netConn.nc != nil {
		fmt.Println("close transport")
		t.netConn.nc.Close()
		t.netConn.nc = nil
	}
	t.netConn.Unlock()
	close(t.sendChn)
}

func (t *Transport) writeLoop() {
	for {
		select {
		case data, ok := <-t.sendChn:
			if !ok {
				fmt.Println("transport send channel closed")
				return
			}

			dataLen := len(data)
			fmt.Printf("data to be send:%d\n", dataLen)
			sendLen := 0
			for {
				num, err := t.netConn.nc.Write(data[sendLen:])
				if err != nil {
					fmt.Printf("conn write error:%s", err.Error())
					break
				}

				sendLen += num
				if dataLen == sendLen {
					fmt.Println("conn write success")
					break
				}
			}
		}
	}
}

//read 读取指定长度字符
func (t *Transport) readPacketHdr() ([]byte, error) {
	data := make([]byte, HeaderLen, 1024)

	readLen := 0

	for {
		num, err := t.netConn.nc.Read(data[readLen:])
		if err != nil {
			fmt.Println(err.Error())
			return nil, err
		}

		readLen += num
		if readLen == HeaderLen {
			return data, nil
		}
	}
}

func (t *Transport) readLoop() {
	for {
		t.netConn.RLock()
		if t.netConn.nc == nil {
			fmt.Printf("t.netConn.nc is nil")
			t.netConn.RUnlock()
			return
		}
		t.netConn.RUnlock()

		h, err := t.readPacketHdr()
		if err != nil {
			if err == io.EOF {
				fmt.Printf("read EOF fail")
				return
			}

			fmt.Printf("read packet header fail:%s", err.Error())
			continue
		} else {
			tacacsType := uint8(h[TypeOffset])
			switch tacacsType {
			case TypeAcct:
			case TypeAuthor:
			case TypeAuthen:
			default:
				fmt.Println("error, invalid tacacs version")
				continue
			}
		}

		recv, err := t.readPacketBody(h)
		if err != nil {
			if err == io.EOF {
				fmt.Println("read Eof, close")
				return
			}

			fmt.Println("read packet header fail:%s", err.Error())
			continue
		}

		fmt.Println("conn read success,dataLen:", len(recv))
		dispatch(recv)
	}
}

func dispatch(data []byte) {

	sessionID := binary.BigEndian.Uint32(data[SessionIDOffset:])
	value, ok := TacacsMng.Sessions.Load(sessionID)
	if ok {
		sess, ok := value.(*Session)
		if ok {
			fmt.Printf("found session,dispatch success\n")
			sess.ReadBuffer <- data
		} else {
			fmt.Printf("*** error, interface assert fail ***")
		}

	} else {
		fmt.Println("error, no invalid session found")
	}
}

func (t *Transport) readPacketBody(data []byte) ([]byte, error) {

	bodyLen := binary.BigEndian.Uint32(data[LengthOffset:])
	if bodyLen > MaxPacketLen {
		return nil, fmt.Errorf("packet too large")
	} else if bodyLen == 0 {
		return nil, fmt.Errorf("empty packet body")
	}

	p := append(data, make([]byte, bodyLen)...)

	startLen := len(data)
	totalLen := len(p)
	for {
		num, err := t.netConn.nc.Read(p[startLen:])
		if err != nil {
			fmt.Println(err.Error())
			return nil, err
		}

		startLen += num
		if startLen == totalLen {
			return p, nil
		}
	}
}
