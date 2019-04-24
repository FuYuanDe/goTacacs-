// packet.go
package main

import (
	"time"
	"errors"
	"strconv"
	"fmt"
	"encoding/binary"
	"crypto/md5"
)

const (
	TacacsMajorVersion        = uint8(0xc << 4)
	TacacsMinorVersionDefault = uint8(0x0)
	TacacsMinorVersionOne     = uint8(0x1)
)

const (
	TacacsTypeAuthen = uint8(0x01)
	TacacsTypeAuthor = uint8(0x02)
	TacacsTypeAcct   = uint8(0x03)
)

const (
	TacacsSingleConnectFlag = uint8(0x04)
	TacplusUnencryptedFlag  = uint8(0x01)
)

/*
				4.8 TACACS+ Packet Header

1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8
+----------------+----------------+----------------+----------------+
|major  | minor  | 				  | 			   |			    |
|version| version| 		type 	  |     seq_no 	   |	  flags     |
+----------------+----------------+----------------+----------------+
| 																	|
| 							 session_id							    |
+----------------+----------------+----------------+----------------+
| 																	|
| 							 	length							    |
+----------------+----------------+----------------+----------------+
*/

//packet offset
const (
	VersionOffset   = 0
	TypeOffset      = 1
	SeqNoOffset     = 2
	FlagsOffset     = 3
	SessionIDOffset = 4
	LengthOffset    = 8
)

const (
	HeaderLen    = 12
	MaxPacketLen = 4096
)

type TacacsHeader struct {
	TacacsVersion   uint8
	TacacsType      uint8
	TacacsSeqNo     uint8
	TacacsFlags     uint8
	TacacsSessionID uint32
	TacacsLength    uint32
}

func (h *TacacsHeader)unmarshal(data []byte){
	h.TacacsVersion = data[VersionOffset]
	h.TacacsType = data[TypeOffset]
	h.TacacsSeqNo = data[SeqNoOffset]
	h.TacacsFlags = data[FlagsOffset]
	h.TacacsSessionID = binary.BigEndian.Uint32(data[SessionIDOffset])
	h.TacacsLength = binary.BigEndian.Uint32(data[LengthOffset])
}

const (
	TacacsAuthenActionLogin    = uint8(0x01)
	TacacsAuthenActionChPass   = uint8(0x02)
	TacacsAuthenActionSendAuth = uint8(0x04)
)

const (
	TacacsAuthenTypeASCII    = uint8(0x01)
	TacacsAuthenTypePAP      = uint8(0x02)
	TacacsAuthenTypeCHAP     = uint8(0x03)
	TacacsAuthenTypeARAP     = uint8(0x04) //(deprecated)
	TacacsAuthenTypeMSCHAP   = uint8(0x05)
	TacacsAuthenTypeMSCHAPV2 = uint8(0x06)
)

const (
	TacacsAuthenServiceNone    = uint8(0x00)
	TacacsAuthenServiceLogin   = uint8(0x01)
	TacacsAuthenServiceEnable  = uint8(0x02)
	TacacsAuthenServicePPP     = uint8(0x03)
	TacacsAuthenServiceARAP    = uint8(0x04)
	TacacsAuthenServicePT      = uint8(0x05)
	TacacsAuthenServiceRCMD    = uint8(0x06)
	TacacsAuthenServiceX25     = uint8(0x07)
	TacacsAuthenServiceNASI    = uint8(0x08)
	TacacsAuthenServiceFWPROXY = uint8(0x09)
)

const (
	TacacsPrivLvlMax  = uint8(0x0f)
	TacacsPrivLvlRoot = uint8(0x0f)
	TacacsPrivLvlUser = uint8(0x01)
	TacacsPrivLvlMin  = uint8(0x00)
)

/*
	5.1. The Authentication START Packet Body

1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8
+----------------+----------------+----------------+----------------+
| action 		 | priv_lvl 	  | authen_type    | service 		|
+----------------+----------------+----------------+----------------+
| user len		 | port len		  | rem_addr len   | data len       |
+----------------+----------------+----------------+----------------+
| user ...
+----------------+----------------+----------------+----------------+
| port ...
+----------------+----------------+----------------+----------------+
| rem_addr ...
+----------------+----------------+----------------+----------------+
| data...
+----------------+----------------+----------------+----------------+
*/

type AuthenStartPacket struct {
	Header     TacacsHeader
	Action     uint8
	PrivLvl    uint8
	AuthenType uint8
	Service    uint8
	UserLen    uint8
	PortLen    uint8
	RmtAddrLen uint8
	DataLen    uint8
	User       string
	Port       string
	RmtAddr    string
	Data       string
}

func GetPort(addr string) (uint16, error) {
	if len(addr) == 0 {
		return 0, errors.New("invalid addr")
	} else {
		offset := strings.LastIndex(addr, ":")
		if offset == -1 {
			return 0, errors.New("invalid addr, no port found")
		} else {
			data := addr[(offset + 1):]
			port, err := strconv.ParseUint(string(data), 10, 16)
			if err != nil {
				return 0, err
			} else {
				return uint16(port), nil
			}
		}
	}
}

func GetIP(addr string) (string, error) {
	if len(addr) == 0 {
		return "", errors.New("invalid addr")
	} else {
		offset := strings.LastIndex(addr, ":")
		if offset == -1 {
			return "", errors.New("invalid addr, no port found")
		} else {
			data := addr[:offset]
			return string(data), nil
		}
	}
}


func AuthenASCII(username, passwd string)error {
	sess := NewSession(TacacsMng.ctx, username, passwd)
	packet := &AuthenStartPacket{}
	packet.Header.TacacsVersion = (TacacsMajorVersion | TacacsMinorVersionDefault)
	packet.Header.TacacsType = TacacsTypeAuthen
	packet.Header.TacacsSeqNo = sess.SessionSeqNo++
	
	if sess.mng.Config.ConnMultiplexing {
		packet.Header.TacacsFlags |= TacacsSingleConnectFlag
	}
	packet.Header.TacacsSessionID = sess.SessionID
	packet.Action = TacacsAuthenActionLogin
	packet.PrivLvl = TacacsPrivLvlRoot
	packet.AuthenType = TacacsAuthenTypeASCII
	packet.Service = TacacsAuthenServiceLogin
	
	totalLen := HeaderLen + 8
	packet.UserLen = uint8(len(username))
	packet.User = username
	totalLen += packet.UserLen
	
	port,err := GetPort(sess.t.netConn.nc.LocalAddr().String())
	if err != nil {
		fmt.Printf("GetPort Fail:%s\n", err.Error())
	}else{
		packet.Port = strconv.FormatUint(uint64(port),16)
		fmt.Printf("LocalPort : %d\n", port)
	}
	packet.PortLen =  uint8(len(packet.Port))
	totalLen += packet.PortLen
	
	addr, err := GetIP(sess.t.netConn.nc.LocalAddr().String())
	if err != nil {
		fmt.Printf("GetIP fail,%s\n", err.Error())
		packet.RmtAddrLen = 0
	}else{
		packet.RmtAddr = addr
		packet.RmtAddrLen = uint8(addr)		
	}
	totalLen += packet.RmtAddrLen
	
	packet.DataLen = 0
	data, err := packet.marshal()
	if err != nil {
		fmt.Printf("packet marshal fail, error msg :%s\n", err.Error())
		return err
	}	
	crypt(data,sess.Password)
	sess.t.sendChn <- data
	select{
		case data := <-sess.ReadBuffer:
		case <- time.After(10*time.Second)
			fmt.Printf("receive reply timeout")
			//关闭连接
			sess.t.close()
			return errors.New("timeout")
	}
	//check version
	reply := &AuthenReplyPacket{}
	reply.Header.unmarshal(data)	
	crypt(data, passwd)		
	reply.unmarshal(data)
	switch reply.Status {
	case TacacsAuthenStatusPass    :
	fmt.Printf("server reply pass\n")
	case TacacsAuthenStatusFail    :
	fmt.Printf("server reply fail\n")
	case TacacsAuthenStatusGetData    :
	fmt.Printf("server reply getdata\n")
	case TacacsAuthenStatusGetUser    :
	fmt.Printf("server reply getuser\n")
	case TacacsAuthenStatusGetPass    :
	fmt.Printf("server reply getpass\n")
	case TacacsAuthenStatusRestart    :
	fmt.Printf("server reply restart\n")
	case TacacsAuthenStatusError    :
	fmt.Printf("server reply error\n")
	case TacacsAuthenStatusFollow    :
	fmt.Printf("server reply follow\n")
	default :
	fmt.Printf("server reply unrecognized\n")
	}
}


func (a *AuthenStartPacket) marshal() ([]byte, error) {
	buf := make([]byte, 1024)
	buf[Version] = a.Header.TacacsVersion
	buf[Type] = a.Header.TacacsType
	buf[SeqNo] = a.Header.TacacsSeqNo
	buf[Flags] = a.Header.TacacsFlags

	binary.BigEndian.PutUint32(buf[SessionID:], a.Header.TacacsSessionID)
	binary.BigEndian.PutUint32(buf[Length:], a.Header.TacacsLength)
	buf = append(buf, a.Action, a.PrivLvl, a.AuthenType, a.Service)
	buf = append(buf, uint8(len(a.User)), uint8(len(a.Port)))
	buf = append(buf, uint8(len(a.RmtAddr)), uint8(len(a.Data)))
	buf = append(buf, a.User...)
	buf = append(buf, a.Port...)
	buf = append(buf, a.RmtAddr...)
	buf = append(buf, a.Data...)

	return buf, nil
}

const (
	TacacsAuthenStatusPass    = 0x01
	TacacsAuthenStatusFail    = 0x02
	TacacsAuthenStatusGetData = 0x03
	TacacsAuthenStatusGetUser = 0x04
	TacacsAuthenStatusGetPass = 0x05
	TacacsAuthenStatusRestart = 0x06
	TacacsAuthenStatusError   = 0x07
	TacacsAuthenStatusFollow  = 0x21
)

const (
	TacacsReplyFlagNoEcho = 0x01
)

const (
	TacacsContinueFlagAbort = 0x01
)

/*
	5.2. The Authentication REPLY Packet Body

1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8
+----------------+----------------+----------------+----------------+
|     status 	 |	   flags 	  | 		  server_msg_len 		|
+----------------+----------------+----------------+----------------+
|     data_len 	 				  |			  server_msg ...
+----------------+----------------+----------------+----------------+
| 	  data ...
+----------------+----------------+
*/

type AuthenReplyPacket struct {
	Header       TacacsHeader
	Status       uint8
	Flags        uint8
	ServerMsgLen uint16
	DataLen      uint16
	ServerMsg    []byte
	Data         []byte
}

func (a *AuthenReplyPacket)unmarshal(data []byte)error{
	body := data[HeaderLen:]
	a.Status = uint8(data[0])
	a.Flags = uint8(data[1])
	a.ServerMsgLen = binary.BigEndian.Uint16(data[2:])
	a.DataLen = binary.BigEndian.Uint16(data[4:])
	if a.ServerMsgLen != 0 {
		a.ServerMsg = data[6:(a.ServerMsgLen+6)]	
	}
	if a.DataLen != 0{
		a.Data = data[(a.ServerMsgLen+6):]
	}
	
	return nil
}

//解密后的数据
func crypt(p, key []byte) {
	buf := make([]byte, len(key)+6)
	copy(buf, p[4:8])      //sessionID
	copy(buf[4:], key)     //key
	buf[len(buf)-2] = p[0] //版本
	buf[len(buf)-1] = p[2] //序列号

	var sum []byte

	h := md5.New()
	//消息体
	body := p[HeaderLen:]

	for len(body) > 0 {
		h.Reset()

		h.Write(buf)
		h.Write(sum)
		sum = h.Sum(nil) //得到首次的校验值

		if len(body) < len(sum) {
			sum = sum[:len(body)]
		}

		for i, c := range sum {
			body[i] ^= c
		}
		body = body[len(sum):]
	}	
}
