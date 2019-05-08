//
// Base on https://tools.ietf.org/html/draft-ietf-opsawg-tacacs-12
//

// packet.go
package tacacs

import (
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	MajorVersion        = uint8(0xc << 4)
	MinorVersionDefault = uint8(0x0)
	MinorVersionOne     = uint8(0x1)
)

const (
	TypeAuthen = uint8(0x01)
	TypeAuthor = uint8(0x02)
	TypeAcct   = uint8(0x03)
)

const (
	SingleConnectFlag = uint8(0x04)
	UnencryptedFlag   = uint8(0x01)
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
	Version   uint8
	Type      uint8
	SeqNo     uint8
	Flags     uint8
	SessionID uint32
	Length    uint32
}

func (h *TacacsHeader) unmarshal(data []byte) {
	h.Version = uint8(data[VersionOffset])
	h.Type = uint8(data[TypeOffset])
	h.SeqNo = uint8(data[SeqNoOffset])
	h.Flags = uint8(data[FlagsOffset])
	h.SessionID = binary.BigEndian.Uint32(data[SessionIDOffset:])
	h.Length = binary.BigEndian.Uint32(data[LengthOffset:])
}

func (h *TacacsHeader) marshal() []byte {
	buf := make([]byte, HeaderLen)
	//fmt.Printf("debug, init buf len:%d\n", len(buf))
	buf[VersionOffset] = h.Version
	buf[TypeOffset] = h.Type
	buf[SeqNoOffset] = h.SeqNo
	buf[FlagsOffset] = h.Flags
	binary.BigEndian.PutUint32(buf[SessionIDOffset:], h.SessionID)
	binary.BigEndian.PutUint32(buf[LengthOffset:], h.Length)
	return buf
}

const (
	AuthenActionLogin    = uint8(0x01)
	AuthenActionChPass   = uint8(0x02)
	AuthenActionSendAuth = uint8(0x04)
)

const (
	AuthenTypeASCII    = uint8(0x01)
	AuthenTypePAP      = uint8(0x02)
	AuthenTypeCHAP     = uint8(0x03)
	AuthenTypeARAP     = uint8(0x04) //(deprecated)
	AuthenTypeMSCHAP   = uint8(0x05)
	AuthenTypeMSCHAPV2 = uint8(0x06)
)

const (
	AuthenServiceNone    = uint8(0x00)
	AuthenServiceLogin   = uint8(0x01)
	AuthenServiceEnable  = uint8(0x02)
	AuthenServicePPP     = uint8(0x03)
	AuthenServiceARAP    = uint8(0x04)
	AuthenServicePT      = uint8(0x05)
	AuthenServiceRCMD    = uint8(0x06)
	AuthenServiceX25     = uint8(0x07)
	AuthenServiceNASI    = uint8(0x08)
	AuthenServiceFWPROXY = uint8(0x09)
)

const (
	PrivLvlMax        = uint8(0x0f)
	PrivLvlRoot       = uint8(0x0f)
	TacacsPrivLvlUser = uint8(0x01)
	PrivLvlMin        = uint8(0x00)
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

type AuthenStart struct {
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

func (a *AuthenStart) marshal() ([]byte, error) {
	buf := (&a.Header).marshal()

	buf = append(buf, a.Action, a.PrivLvl, a.AuthenType, a.Service)
	buf = append(buf, uint8(len(a.User)), uint8(len(a.Port)))
	buf = append(buf, uint8(len(a.RmtAddr)), uint8(len(a.Data)))
	//fmt.Printf("userLen:%d, portLen:%d,rmtAddrLen:%d,dataLen:%d\n", uint8(len(a.User)), uint8(len(a.Port)), uint8(len(a.RmtAddr)), uint8(len(a.Data)))
	buf = append(buf, a.User...)
	buf = append(buf, a.Port...)
	buf = append(buf, a.RmtAddr...)
	buf = append(buf, a.Data...)
	return buf, nil
}

func (a *AuthenStart) unmarshal() {

}

const (
	AuthenStatusPass    = uint8(0x01)
	AuthenStatusFail    = uint8(0x02)
	AuthenStatusGetData = uint8(0x03)
	AuthenStatusGetUser = uint8(0x04)
	AuthenStatusGetPass = uint8(0x05)
	AuthenStatusRestart = uint8(0x06)
	AuthenStatusError   = uint8(0x07)
	AuthenStatusFollow  = uint8(0x21)
)

const (
	ReplyFlagNoEcho = uint8(0x01)
)

const (
	ContinueFlagAbort = uint8(0x01)
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
	ServerMsg    string
	Data         string
}

func (a *AuthenReplyPacket) unmarshal(data []byte) error {
	a.Status = uint8(data[0])

	a.Flags = uint8(data[1])

	a.ServerMsgLen = binary.BigEndian.Uint16(data[2:])
	//fmt.Printf("status and flags : %x,%x\n", data[0], data[1])

	//fmt.Printf("ServerMsg len :%d,DataLen:%d\n", a.ServerMsgLen, a.DataLen)
	a.DataLen = binary.BigEndian.Uint16(data[4:])

	if a.ServerMsgLen != 0 {
		a.ServerMsg = string(data[6:(a.ServerMsgLen + 6)])
		//fmt.Println("server msg: " + string(a.ServerMsg))
	}

	if a.DataLen != 0 {
		a.Data = string(data[(a.ServerMsgLen + 6):])
		//fmt.Println("data msg : " + string(a.Data))
	}

	return nil
}

func (a *AuthenReplyPacket) marshal() {

}

func (a *AuthenReplyPacket) varify(s *Session) error {
	//check version
	//if a.Header.Version != (MajorVersion | MinorVersionDefault) {
	//	fmt.Printf("version:%d, expect:%d\n", a.Header.Version, (MajorVersion | MinorVersionDefault))
	//	return errors.New("version mismatch")
	//}

	//check flag
	if a.Header.Flags == 1 {
		s.mng.Lock()
		if !s.mng.ServerConnMultiplexing {
			s.mng.ServerConnMultiplexing = true
			fmt.Println("server support ConnMultiplexing")
		}
		s.mng.Unlock()
	}

	//check seqNo
	s.Lock()
	if a.Header.SeqNo == s.SessionSeqNo {
		if s.SessionSeqNo == 255 {
			s.restart = true
			s.Unlock()
			return errors.New("session seqNo overflow,restart")
		} else {
			s.SessionSeqNo++
		}
	}
	s.Unlock()

	//check sessionID
	return nil
}

/*
 *		Authen Continue Packet
 *	0                7                15               23               31
 *	+----------------+----------------+----------------+----------------+
 *	| 			user_msg len 		  |				 data_len 			|
 *	+----------------+----------------+----------------+----------------+
 *	| flags 		 |					 user_msg ...
 *	+----------------+----------------+----------------+----------------+
 *	| data ...
 *	+----------------+
 */

type AuthenContinuePacket struct {
	Header     TacacsHeader
	UserMsgLen uint16
	DataLen    uint16
	Flags      uint8
	Data       string
	UserMsg    string
}

//版本应该根据认证类型来确定TODO
func (p *AuthenContinuePacket) init(s *Session) {
	s.Lock()
	defer s.Unlock()
	p.Header.Version = (MajorVersion | MinorVersionDefault)
	p.Header.Type = TypeAuthen
	p.Header.SeqNo = s.SessionSeqNo
	s.SessionSeqNo++
	s.mng.Lock()
	if s.mng.Config.ConnMultiplexing {
		p.Header.Flags |= SingleConnectFlag
	}
	s.mng.Unlock()

	p.Header.SessionID = s.SessionID
	p.DataLen = 0
	p.Header.Length = uint32(5 + len(s.Password))
	fmt.Printf("continue packet len:%d\n", p.Header.Length)
	p.UserMsgLen = uint16(len(s.Password))
	p.UserMsg = s.Password
}

func (p *AuthenContinuePacket) marshal() ([]byte, error) {
	//buf := make([]byte, p.Header.Length+HeaderLen)

	buf := p.Header.marshal()
	buf = append(buf, make([]byte, 4)...)
	binary.BigEndian.PutUint16(buf[HeaderLen:], p.UserMsgLen)
	binary.BigEndian.PutUint16(buf[(HeaderLen+2):], p.DataLen)
	//fmt.Printf("continue packet totlen: %d\n", len(buf))
	buf = append(buf, p.Flags)
	//fmt.Printf("continue packet totlen: %d\n", len(buf))
	buf = append(buf, p.UserMsg...)
	//fmt.Printf("continue packet totlen: %d\n", len(buf))
	buf = append(buf, p.Data...)
	//fmt.Printf("continue packet totlen: %d\n", len(buf))
	return buf, nil
}

func (p *AuthenContinuePacket) unmarshal() {

}

//
//	CP4.7. Data Obfuscation
//
//	ENCRYPTED {data} = data ^ pseudo_pad
//
//	pseudo_pad = {MD5_1 [,MD5_2 [ ... ,MD5_n]]} truncated to len(data)
//
//	MD5_1 = MD5{session_id, key, version, seq_no}
//	MD5_2 = MD5{session_id, key, version, seq_no, MD5_1}
//	....
//	MD5_n = MD5{session_id, key, version, seq_no, MD5_n-1}
//
//
func crypt(p, key []byte) {
	buf := make([]byte, len(key)+6)
	copy(buf, p[4:8])      //sessionID
	copy(buf[4:], key)     //key
	buf[len(buf)-2] = p[0] //version
	buf[len(buf)-1] = p[2] //seqno

	var sum []byte

	h := md5.New()

	body := p[HeaderLen:]
	//fmt.Printf("crypt body len:%d\n", len(body))

	for len(body) > 0 {
		h.Reset()

		h.Write(buf)
		h.Write(sum)
		sum = h.Sum(nil)

		if len(body) < len(sum) {
			sum = sum[:len(body)]
		}

		for i, c := range sum {
			body[i] ^= c
		}
		body = body[len(sum):]
	}
}

//6.1. The Authorization REQUEST Packet Body
//
//0				 7				  15			   23				31
//+----------------+----------------+----------------+----------------+
//| authen_method  | 	  priv_lvl  |   authen_type  | authen_service |
//+----------------+----------------+----------------+----------------+
//| user_len 	   |	  port_len  |   rem_addr_len | arg_cnt 		  |
//+----------------+----------------+----------------+----------------+
//| arg_1_len 	   |      arg_2_len | ... 	         | arg_N_len  	  |
//+----------------+----------------+----------------+----------------+
//| user ...
//+----------------+----------------+----------------+----------------+
//| port ...
//+----------------+----------------+----------------+----------------+
//| rem_addr ...
//+----------------+----------------+----------------+----------------+
//| arg_1 ...
//+----------------+----------------+----------------+----------------+
//| arg_2 ...
//+----------------+----------------+----------------+----------------+
//| ...
//+----------------+----------------+----------------+----------------+
//| arg_N ...
//+----------------+----------------+----------------+----------------+
//

//authen_method
//
//This indicates the authentication method used by the client to
//acquire the user information. As this information is not always
//subject to verification, it is recommended that this field is
//ignored.
//
const (
	AuthenMethodNotSet     = uint8(0x00)
	AuthenMethodNone       = uint8(0x01)
	AuthenMethodKRB5       = uint8(0x02)
	AuthenMethodLINE       = uint8(0x03)
	AuthenMethodEnable     = uint8(0x04)
	AuthenMethodLocal      = uint8(0x05)
	AuthenMethodTACACSPLUS = uint8(0x06)

	AuthenMethodGuest  = uint8(0x08)
	AuthenMethodRADIUS = uint8(0x10)
	AuthenMethodKRB4   = uint8(0x11)
	AuthenMethodRCMD   = uint8(0x20)
)

//
//authen_type
//
//This field coresponds to the authen_type field in the authentication
//section (Section 5) above. It indicates the type of authentication
//that was performed. If this information is not available, then the
//client will set authen_type to: TAC_PLUS_AUTHEN_TYPE_NOT_SET := 0x00.
//This value is valid only in authorization and accounting requests.
//
const (
	AuthenTypeNotSet = uint8(0x00)
)

type AuthorRequest struct {
	Header        TacacsHeader
	AuthenMethod  uint8
	PrivLvl       uint8
	AuthenType    uint8
	AuthenService uint8
	UserLen       uint8
	PortLen       uint8
	RmtAddrLen    uint8
	ArgCnt        uint8
	//Arg1Len	uint8
	//Arg2Len	uint8
	//...
	//ArgNLen	uint8
}

func (p *AuthorRequest) marshal() []byte {
	//buf := make([]byte, HeaderLen+8)
	buf := p.Header.marshal()
	buf = append(buf, p.AuthenMethod, p.PrivLvl, p.AuthenType, p.AuthenService)
	buf = append(buf, p.UserLen, p.PortLen, p.RmtAddrLen, p.ArgCnt)
	return buf
}

//6.2. The Authorization REPLY Packet Body
//
//1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8
//+----------------+----------------+----------------+----------------+
//| status 		   | arg_cnt 		| server_msg len				  |
//+----------------+----------------+----------------+----------------+
//+ data_len 						| arg_1_len 	 | arg_2_len	  |
//+----------------+----------------+----------------+----------------+
//| ... 		   | arg_N_len		| server_msg ...
//+----------------+----------------+----------------+----------------+
//| data ...
//+----------------+----------------+----------------+----------------+
//| arg_1 ...
//+----------------+----------------+----------------+----------------+
//| arg_2 ...
//+----------------+----------------+----------------+----------------+
//| ...
//+----------------+----------------+----------------+----------------+
//| arg_N ...
//+----------------+----------------+----------------+----------------+
//
//
const (
	AuthorStatusPassAdd  = uint8(0x01)
	AuthorStatusPassREPL = uint8(0x02)
	AuthorStatusFail     = uint8(0x10)
	AuthorStatusError    = uint8(0x11)
	AuthorStatusFollow   = uint8(0x21)
)

type AuthorReply struct {
	Header       TacacsHeader
	Status       uint8
	ArgCnt       uint8
	ServerMsgLen uint16
	DataLen      uint16
	//Arg1Len
	//Arg2Len
	//...
	//ArgNLen
	//ServerMsg
	//Data
	//Arg1
	//Arg2
	//...
	//ArgN
}

func (p *AuthorReply) unmarshal(data []byte) {
	(&p.Header).unmarshal(data)
	p.Status = uint8(data[0+HeaderLen])
	p.ArgCnt = uint8(data[1+HeaderLen])
	p.ServerMsgLen = binary.BigEndian.Uint16(data[(2 + HeaderLen):])
	p.DataLen = binary.BigEndian.Uint16(data[(4 + HeaderLen):])
}

func (p *AuthorReply) SanityCheck(sess *Session, data []byte) error {
	if p.Header.Version != (MajorVersion | MinorVersionDefault) {
		return errors.New("invalid version, author reply check fail")
	}

	//check Single Connect Flag
	if (p.Header.Flags & SingleConnectFlag) == 1 {
		sess.mng.Lock()
		if !sess.mng.ServerConnMultiplexing {
			sess.mng.ServerConnMultiplexing = true
			fmt.Println("server support ConnMultiplexing")
		}
		sess.mng.Unlock()
	}

	//check unencrypted flag, only set when debug
	if (p.Header.Flags & UnencryptedFlag) == 1 {
		fmt.Printf("Warning! unencrypted packet,not support\n")
		return errors.New("Warning! unencrypted packet,not support")
	}

	//check seqNo
	sess.Lock()
	if p.Header.SeqNo == sess.SessionSeqNo {
		if sess.SessionSeqNo == 255 {
			sess.restart = true
			sess.Unlock()
			return errors.New("session seqNo overflow,restart")
		} else {
			sess.SessionSeqNo++
		}
	}
	sess.Unlock()

	if len(data) != int(p.Header.Length+HeaderLen) {
		fmt.Printf("invalid author response,recv:%d, hdr->len:%d\n", len(data), int(p.Header.Length+HeaderLen))
		return errors.New("invalid author response, packet size not match")
	}

	return nil
}

//
//7.1. The Account REQUEST Packet Body
//
//1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8
//+----------------+----------------+----------------+----------------+
//| flags 		   | authen_method  | priv_lvl 		 | authen_type 	  |
//+----------------+----------------+----------------+----------------+
//| authen_service | user_len 		| port_len 		 | rem_addr_len   |
//+----------------+----------------+----------------+----------------+
//| arg_cnt 	   | arg_1_len		| arg_2_len      | ... 			  |
//+----------------+----------------+----------------+----------------+
//| arg_N_len 	   | user ...
//+----------------+----------------+----------------+----------------+
//| port ...
//+----------------+----------------+----------------+----------------+
//| rem_addr ...
//+----------------+----------------+----------------+----------------+
//| arg_1 ...
//+----------------+----------------+----------------+----------------+
//| arg_2 ...
//+----------------+----------------+----------------+----------------+
//| ...
//+----------------+----------------+----------------+----------------+
//| arg_N ...
//+----------------+----------------+----------------+----------------+
//

const (
	AcctFlagStart    = uint8(0x02)
	AcctFlagStop     = uint8(0x04)
	AcctFlagWatchDog = uint8(0x08)
)

type AccountRequest struct {
	Header        TacacsHeader
	Flags         uint8
	AuthenMethod  uint8
	PrivLvl       uint8
	AuthenType    uint8
	AuthenService uint8
	UserLen       uint8
	PortLen       uint8
	RmtAddrLen    uint8
	ArgCnt        uint8
	//Arg1Len  uint8
	//ArgNLen  uint8
	//user string
	//port string
	//...
}

func (p *AccountRequest) marshal() []byte {
	buf := (&p.Header).marshal()

	buf = append(buf, p.Flags, p.AuthenMethod, p.PrivLvl, p.AuthenType, p.AuthenService)
	buf = append(buf, p.UserLen, p.PortLen, p.RmtAddrLen, p.ArgCnt)
	return buf
}

//7.2. The Accounting REPLY Packet Body
//
//The purpose of accounting is to record the action that has occurred
//on the client. The server MUST reply with success only when the
//accounting request has been recorded. If the server did not record
//the accounting request then it MUST reply with ERROR.
//
//1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8
//+----------------+----------------+----------------+----------------+
//| server_msg len 				 	| data_len 						  |
//+----------------+----------------+----------------+----------------+
//| status 		   | server_msg ...
//+----------------+----------------+----------------+----------------+
//| data ...
//+----------------+
//

const (
	AccountStatusSuccess = uint8(0x01)
	AccountStatusError   = uint8(0x02)
	AccountStatusFollow  = uint8(0x21)
)

type AccountReply struct {
	Header       TacacsHeader
	ServerMsgLen uint16
	DataLen      uint16
	Status       uint8
	ServerMsg    string
	Data         string
}

func (p *AccountReply) marshal() {
	//TODO
}

func (p *AccountReply) unmarshal(data []byte) {
	(&p.Header).unmarshal(data)
	p.ServerMsgLen = binary.BigEndian.Uint16(data[HeaderLen:])
	p.DataLen = binary.BigEndian.Uint16(data[(2 + HeaderLen):])
	p.Status = uint8(data[4+HeaderLen])

	if p.ServerMsgLen != 0 {
		p.ServerMsg = string(data[(HeaderLen + 5):(p.ServerMsgLen + HeaderLen + 5)])
		//fmt.Println("server msg: " + string(a.ServerMsg))
	}

	if p.DataLen != 0 {
		p.Data = string(data[(p.ServerMsgLen + 5 + HeaderLen):])
		//fmt.Println("data msg : " + string(a.Data))
	}
}

func (p *AccountReply) SanityCheck(sess *Session, data []byte) error {
	if p.Header.Version != (MajorVersion | MinorVersionDefault) {
		return errors.New("invalid version, author reply check fail")
	}

	//check Single Connect Flag
	if (p.Header.Flags & SingleConnectFlag) == 1 {
		sess.mng.Lock()
		if !sess.mng.ServerConnMultiplexing {
			sess.mng.ServerConnMultiplexing = true
			fmt.Println("server support ConnMultiplexing")
		}
		sess.mng.Unlock()
	}

	//check unencrypted flag, only set when debug
	if (p.Header.Flags & UnencryptedFlag) == 1 {
		fmt.Printf("Warning! unencrypted packet,not support\n")
		return errors.New("Warning! unencrypted packet,not support")
	}

	//check seqNo
	sess.Lock()
	if p.Header.SeqNo == sess.SessionSeqNo {
		if sess.SessionSeqNo == 255 {
			sess.restart = true
			sess.Unlock()
			return errors.New("session seqNo overflow,restart")
		} else {
			sess.SessionSeqNo++
		}
	}
	sess.Unlock()

	if len(data) != int(p.Header.Length+HeaderLen) {
		fmt.Printf("invalid author response,recv:%d, hdr->len:%d\n", len(data), int(p.Header.Length+HeaderLen))
		return errors.New("invalid author response, packet size not match")
	}

	return nil
}
