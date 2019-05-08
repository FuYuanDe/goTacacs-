package tacacs

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

//12. Table 1: Attribute-value Pairs
//
//service
//The primary service. Specifying a service attribute indicates that
//this is a request for authorization or accounting of that service.
//Current values are "slip", "ppp", "arap", "shell", "tty-daemon",
//"connection", "system" and "firewall". This attribute MUST always be
//included.
//
//protocol
//a protocol that is a subset of a service. An example would be any PPP
//NCP. Currently known values are "lcp", "ip", "ipx", "atalk", "vines",
//"lat", "xremote", "tn3270", "telnet", "rlogin", "pad", "vpdn", "ftp",
//"http", "deccp", "osicp" and "unknown".
//
//....
//

func AuthorStart(sess *Session, authorMethod, privLvl, authorType, authorSvc uint8, AttrValuePair ...string) []byte {
	p := &AuthorRequest{}
	p.Header.Version = (MajorVersion | MinorVersionDefault)
	p.Header.Type = TypeAuthor
	p.Header.SeqNo = sess.SessionSeqNo
	sess.SessionSeqNo++
	if sess.mng.Config.ConnMultiplexing {
		p.Header.Flags |= SingleConnectFlag
	}
	p.Header.SessionID = sess.SessionID
	p.Header.Length = 8
	p.AuthenMethod = authorMethod
	p.PrivLvl = privLvl
	p.AuthenType = authorType
	p.AuthenService = authorSvc
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
	p.ArgCnt = uint8(len(AttrValuePair))
	if p.ArgCnt != 0 {
		p.Header.Length += uint32(len(AttrValuePair))
		for _, arg := range AttrValuePair {
			fmt.Printf("arg:%s,len:%d\n", arg, len(arg))
			p.Header.Length += uint32(len(arg))
		}
	}

	buf := p.marshal()
	if p.ArgCnt != 0 {
		for _, arg := range AttrValuePair {
			buf = append(buf, uint8(len(arg)))
		}
	}

	buf = append(buf, sess.UserName...)
	if p.PortLen != 0 {
		buf = append(buf, (strconv.FormatUint(uint64(port), 16))...)
	}
	buf = append(buf, addr...)
	for _, arg := range AttrValuePair {
		buf = append(buf, arg...)
	}
	fmt.Printf("len(AuthorRequest):%d\n", len(buf))
	crypt(buf, []byte(sess.mng.Config.ShareKey))
	return buf
}

func AuthorResponse(sess *Session, data []byte) error {
	p := &AuthorReply{}
	crypt(data, []byte(sess.mng.Config.ShareKey))
	p.unmarshal(data)

	err := p.SanityCheck(sess, data)
	if err != nil {
		return err
	}

	switch p.Status {
	//
	//If the status equals TAC_PLUS_AUTHOR_STATUS_PASS_ADD, then the
	//arguments specified in the request are authorized and the arguments in
	//the response are to be used IN ADDITION to those arguments.
	//
	case AuthorStatusPassAdd:

		fmt.Printf("Author success\n")

		return nil
	//
	//If the status equals TAC_PLUS_AUTHOR_STATUS_PASS_REPL then the
	//arguments in the request are to be completely replaced by the
	//arguments in the response.
	//
	case AuthorStatusPassREPL:
		fmt.Printf("Server Response REPLACE	")
		return nil
	case AuthorStatusFail:
		return errors.New("Server Response Fail")
	case AuthorStatusError:
		return errors.New("Server Response Error")
	case AuthorStatusFollow:
		return errors.New("Server Response Follow")
	default:
		fmt.Printf("unsupported author response status:%d\n", p.Status)
		return errors.New("unsupported author response status")
	}
}

func Author(sess *Session, authorMethod, privLvl, authorType, authorSvc uint8, AttrValuePair ...string) error {

	//prepare the start packet
	data := AuthorStart(sess, authorMethod, privLvl, authorType, authorSvc, AttrValuePair...)
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
			fmt.Println("receive author reply,len:", len(buffer))
			return AuthorResponse(sess, buffer)

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
