// account.go
package tacacs

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

type AccountConfig struct {
	Flags         uint8
	AuthenMethod  uint8
	PrivLvl       uint8
	AuthenType    uint8
	AuthenService uint8
}

func AccountStart(sess *Session, cfg AccountConfig, Attr ...string) []byte {
	p := AccountRequest{}
	p.Header.Version = (MajorVersion | MinorVersionDefault)
	p.Header.Type = TypeAcct
	p.Header.SeqNo = sess.SessionSeqNo
	sess.SessionSeqNo++
	sess.mng.RLock()
	if sess.mng.Config.ConnMultiplexing {
		p.Header.Flags |= SingleConnectFlag
	}
	sess.mng.RUnlock()

	p.Header.SessionID = sess.SessionID
	p.Header.Length = 9
	p.Flags = cfg.Flags
	p.AuthenMethod = cfg.AuthenMethod
	p.PrivLvl = cfg.PrivLvl
	p.AuthenType = cfg.AuthenType
	p.AuthenService = cfg.AuthenService

	p.UserLen = uint8(len(sess.UserName))
	p.Header.Length += uint32(p.UserLen)

	port, err := GetPort(sess.t.netConn.nc.LocalAddr().String())
	if err != nil {
		fmt.Printf("GetPort Fail:%s\n", err.Error())
	} else {

		//packet.Port = strconv.FormatUint(uint64(port), 16)
		//fmt.Printf("LocalPort : %d\n", port)
		p.PortLen = uint8(len(strconv.FormatUint(uint64(port), 16)))
	}
	p.Header.Length += uint32(p.PortLen)

	addr, err := GetIP(sess.t.netConn.nc.LocalAddr().String())
	if err != nil {
		fmt.Printf("GetIP fail,%s\n", err.Error())
		p.RmtAddrLen = 0
	} else {
		p.RmtAddrLen = uint8(len(addr))
	}
	p.Header.Length += uint32(p.RmtAddrLen)

	p.ArgCnt = uint8(len(Attr))
	if p.ArgCnt != 0 {
		p.Header.Length += uint32(len(Attr))
		for _, arg := range Attr {
			fmt.Printf("arg:%s,len:%d\n", arg, len(arg))
			p.Header.Length += uint32(len(arg))
		}
	}

	buf := p.marshal()
	if p.ArgCnt != 0 {
		for _, arg := range Attr {
			buf = append(buf, uint8(len(arg)))
		}
	}

	buf = append(buf, sess.UserName...)
	if p.PortLen != 0 {
		buf = append(buf, (strconv.FormatUint(uint64(port), 16))...)
	}
	buf = append(buf, addr...)
	for _, arg := range Attr {
		buf = append(buf, arg...)
	}
	fmt.Printf("len(AccountRequest):%d\n", len(buf))
	crypt(buf, []byte(sess.mng.Config.ShareKey))
	return buf
}

func AccountResponse(sess *Session, data []byte) error {
	p := &AccountReply{}

	crypt(data, []byte(sess.mng.Config.ShareKey))
	p.unmarshal(data)

	err := p.SanityCheck(sess, data)
	if err != nil {
		return err
	}

	switch p.Status {
	case AccountStatusSuccess:
		fmt.Printf("Account success\n")
		return nil

	case AccountStatusError:
		fmt.Printf("Server Response REPLACE	")
		return errors.New("Server Response Error")

	case AccountStatusFollow:
		return errors.New("Server Response Follow")

	default:
		fmt.Printf("unsupported account response status:%d\n", p.Status)
		return errors.New("unsupported author response status")
	}
}

func Account(sess *Session, cfg AccountConfig, Attr ...string) error {

	//prepare the request packet
	data := AccountStart(sess, cfg, Attr...)
	sess.t.Lock()
	if !sess.t.Done {
		fmt.Printf("write len:%d\n", len(data))
		sess.t.sendChn <- data
	} else {
		fmt.Println("transport buffer closed, ASCIIAuthen fail")
		sess.t.Unlock()
		sess.close()
		return errors.New("transport buffer closed, ASCIIAuthen fail")
	}
	sess.t.Unlock()

	//waitting for server reply
	for {
		select {
		case buffer := <-sess.ReadBuffer:
			fmt.Println("receive account reply,len:", len(buffer))
			return AccountResponse(sess, buffer)

		case <-time.After(time.Duration(sess.timeout) * time.Second):
			fmt.Printf("receive reply timeout\n")
			//关闭连接
			//sess.close()
			return errors.New("timeout")

		case <-sess.ctx.Done():
			fmt.Printf("sess close")
			//sess.close()
			return errors.New("session close")
		}
	}
}
