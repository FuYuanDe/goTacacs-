// packet.go
package main

import (
	"fmt"
)

const (
	TacacsMajorVersion        = 0xc
	TacacsMinorVersionDefault = 0x0
	TacacsMinorVersionOne     = 0x1
)

const (
	TacacsTypeAuthen = 0x01
	TacacsTypeAuthor = 0x02
	TacacsTypeAcct   = 0x03
)

const (
	TacacsSingleConnectFlag = 0x04
	TacplusUnencryptedFlag  = 0x1
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

type TacacsHeader struct {
	TacacsVersion   uint8
	TacacsType      uint8
	TacacsSeqNo     uint8
	TacacsFlags     uint8
	TacacsSessionID uint32
	TacacsLength    uint32
}

const (
	TacacsAuthenActionLogin    = 0x01
	TacacsAuthenActionChPass   = 0x02
	TacacsAuthenActionSendAuth = 0x04
)

const (
	TacacsAuthenTypeASCII    = 0x01
	TacacsAuthenTypePAP      = 0x02
	TacacsAuthenTypeCHAP     = 0x03
	TacacsAuthenTypeARAP     = 0x04 //(deprecated)
	TacacsAuthenTypeMSCHAP   = 0x05
	TacacsAuthenTypeMSCHAPV2 = 0x06
)

const (
	TacacsAuthenServiceNone    = 0x00
	TacacsAuthenServiceLogin   = 0x01
	TacacsAuthenServiceEnable  = 0x02
	TacacsAuthenServicePPP     = 0x03
	TacacsAuthenServiceARAP    = 0x04
	TacacsAuthenServicePT      = 0x05
	TacacsAuthenServiceRCMD    = 0x06
	TacacsAuthenServiceX25     = 0x07
	TacacsAuthenServiceNASI    = 0x08
	TacacsAuthenServiceFWPROXY = 0x09
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
	User       string
	Port       string
	RmtAddr    string
	Data       string
}

func (a *AuthenStartPacket) marshal(buf []byte) ([]byte, error) {
	buf = append(buf, a.Header.TacacsVersion, a.Header.TacacsType, a.Header.TacacsSeqNo, a.Header.TacacsFlags)
	buf = append(buf, a.Header.TacacsSessionID, a.Header.TacacsLength)
	buf = append(buf, uint8(len(a.User)), uint8(len(a.Port)), uint8(len(a.RmtAddr)), uint8(len(a.Data)))
	buf = append(buf, a.User...)
	buf = append(buf, a.Port)
	buf = append(buf, a.RmtAddr)
	buf = append(buf, a.Data)

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

//解密后的数据
