// authen.go
package tacacs

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

func ASCIILoginStart(sess *Session) ([]byte, error) {
	sess.Lock()
	defer sess.Unlock()

	packet := &AuthenStart{}
	packet.Header.Version = (MajorVersion | MinorVersionDefault)
	packet.Header.Type = TypeAuthen
	packet.Header.SeqNo = sess.SessionSeqNo
	sess.SessionSeqNo++
	if sess.mng.Config.ConnMultiplexing {
		packet.Header.Flags |= SingleConnectFlag
	}
	packet.Header.SessionID = sess.SessionID
	packet.Action = AuthenActionLogin
	packet.PrivLvl = PrivLvlRoot
	packet.AuthenType = AuthenTypeASCII
	packet.Service = AuthenServiceLogin

	totalLen := 8
	packet.UserLen = uint8(len(sess.UserName))
	packet.User = sess.UserName
	totalLen += int(packet.UserLen)
	//fmt.Printf("userLen:%d\n", int(packet.UserLen))

	port, err := GetPort(sess.t.netConn.nc.LocalAddr().String())
	if err != nil {
		fmt.Printf("GetPort Fail:%s\n", err.Error())
	} else {
		packet.Port = strconv.FormatUint(uint64(port), 16)
		//fmt.Printf("LocalPort : %d\n", port)
	}
	packet.PortLen = uint8(len(packet.Port))
	//fmt.Printf("portLen:%d\n", int(len(packet.Port)))
	totalLen += int(packet.PortLen)

	addr, err := GetIP(sess.t.netConn.nc.LocalAddr().String())
	if err != nil {
		fmt.Printf("GetIP fail,%s\n", err.Error())
		packet.RmtAddrLen = 0
	} else {
		packet.RmtAddr = addr
		packet.RmtAddrLen = uint8(len(addr))
	}
	//fmt.Printf("addr:%d\n", int(len(addr)))
	totalLen += int(packet.RmtAddrLen)

	packet.DataLen = 0
	packet.Header.Length = uint32(totalLen)
	//fmt.Printf("total len :%d\n", totalLen)

	data, err := packet.marshal()
	if err != nil {
		fmt.Printf("packet marshal fail, error msg :%s\n", err.Error())
		return nil, err
	} else {
		//fmt.Printf("total byte :%d\n", len(data))
		crypt(data, []byte(sess.mng.Config.ShareKey))
		return data, nil
	}
}

func ASCIILoginContinue(sess *Session) error {
	data := &AuthenContinuePacket{}
	data.init(sess)
	Buf, err := data.marshal()
	if err != nil {
		fmt.Printf("continue packet marshal fail\n")
		return errors.New("continue packet marshal fail")
	} else {
		crypt(Buf, []byte(sess.mng.Config.ShareKey))
		sess.t.Lock()
		defer sess.t.Unlock()
		if sess.t.Done {
			return errors.New("transport exit, send continue packet fail")
		}
		sess.t.sendChn <- Buf
		fmt.Println("send continue packet to transport buffer")
		return nil
	}
}

func ASCIILoginReply(sess *Session, buffer []byte) (bool, error) {
	reply := &AuthenReplyPacket{}
	(&(reply.Header)).unmarshal(buffer)

	err := reply.varify(sess)
	if err != nil {
		fmt.Printf("%s\n", err.Error())
		return false, err
	}
	//解密
	crypt(buffer, []byte(sess.mng.Config.ShareKey))

	body := buffer[HeaderLen:]
	reply.unmarshal(body)

	switch reply.Status {
	case AuthenStatusPass:
		fmt.Printf("server reply pass\n")
		return true, nil

	case AuthenStatusFail:
		fmt.Printf("server reply fail\n")
		return false, errors.New("server reply fail")

	case AuthenStatusGetData:
		fmt.Printf("server reply getdata\n")
		return false, errors.New("unsupported option,server reply getdata")

	case AuthenStatusGetUser:
		fmt.Printf("server reply getuser\n")
		return false, errors.New("unsupported option,server reply getuser")

	case AuthenStatusGetPass:
		fmt.Printf("server reply getpass\n")
		return false, ASCIILoginContinue(sess)

	case AuthenStatusRestart:
		fmt.Printf("server reply restart\n")
		return false, errors.New("unsupported option,server reply restart")

	case AuthenStatusError:
		fmt.Printf("server reply error\n")
		return false, errors.New("server reply error")

	case AuthenStatusFollow:
		fmt.Printf("server reply follow\n")
		return false, errors.New("unsupported option,server reply follow")

	default:
		fmt.Printf("server reply unrecognized,%d\n", reply.Status)
		msg := fmt.Sprint("%s %d", "server reply unrecognized", reply.Status)
		return false, errors.New(msg)
	}
}

//5.4.2.1. ASCII Login
//
//action = TAC_PLUS_AUTHEN_LOGIN
//authen_type = TAC_PLUS_AUTHEN_TYPE_ASCII
//minor_version = 0x0
//
//This is a standard ASCII authentication. The START packet MAY
//contain the username. If the user does not include the username then
//the server MUST obtain it from the client with a CONTINUE
//TAC_PLUS_AUTHEN_STATUS_GETUSER. If the user does not provide a
//username then the server can send another
//TAC_PLUS_AUTHEN_STATUS_GETUSER request, but the server MUST limit the
//number of retries that are permitted, recommended limit is three
//attempts. When the server has the username, it will obtain the
//password using a continue with TAC_PLUS_AUTHEN_STATUS_GETPASS. ASCII
//login uses the user_msg field for both the username and password.
//The data fields in both the START and CONTINUE packets are not used
//for ASCII logins, any content MUST be ignored. The session is
//composed of a single START followed by zero or more pairs of REPLYs
//and CONTINUEs, followed by a final REPLY indicating PASS, FAIL or
//ERROR.
func AuthenASCII(timeout int, username, password string) error {
	if TacacsMng == nil {
		return errors.New("[tacacs] tacacs hasn't init, Authen fail, exit!")
	} else {
		sess, err := NewSession(TacacsMng.ctx, timeout, username, password)
		if err != nil {
			fmt.Printf("[tacacs] new session fail, %s", err.Error())
			return err
		} else {
			//prepare the start packet
			data, err := ASCIILoginStart(sess)
			if err != nil {
				fmt.Printf("[tacacs] new session fail, %s", err.Error())
				sess.close()
				return err
			} else {
				sess.t.Lock()
				if !sess.t.Done {
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
						done, err := ASCIILoginReply(sess, buffer)
						if err != nil {
							sess.close()
							fmt.Printf("authen fail,error %s\n", err.Error())
							return err
						} else if done {
							fmt.Printf("authen success\n")
							return nil
						}
					case <-time.After(time.Duration(sess.timeout) * time.Second):
						fmt.Printf("receive reply timeout\n")
						//关闭连接
						sess.close()
						return errors.New("timeout")
					case <-sess.ctx.Done():
						fmt.Printf("sess close")
						sess.close()
						return errors.New("session close")
					}
				}
			}
		}
	}
}

//5.4.2.2. PAP Login
//
//action = TAC_PLUS_AUTHEN_LOGIN
//authen_type = TAC_PLUS_AUTHEN_TYPE_PAP
//minor_version = 0x1
//
//The entire exchange MUST consist of a single START packet and a
//single REPLY. The START packet MUST contain a username and the data
//field MUST contain the PAP ASCII password. A PAP authentication only
//consists of a username and password RFC 1334 [RFC1334] . The REPLY
//from the server MUST be either a PASS, FAIL or ERROR.
func AuthenPAP(timeout int, username, password string) error {
	if TacacsMng == nil {
		return errors.New("[tacacs] tacacs hasn't init, AuthenPAP fail, exit!")
	} else {
		sess, err := NewSession(TacacsMng.ctx, timeout, username, password)
		if err != nil {
			fmt.Printf("[tacacs] new session fail, %s", err.Error())
			return err
		} else {
			//prepare the start packet
			data, err := PAPAuthenStart(sess)
			if err != nil {
				fmt.Printf("[tacacs] new session fail, %s", err.Error())
				sess.close()
				return err
			} else {
				sess.t.Lock()
				if !sess.t.Done {
					sess.t.sendChn <- data
				} else {
					fmt.Println("transport buffer closed, PAPAuthen fail")
					sess.t.Unlock()
					sess.close()
					return errors.New("transport buffer closed, PAPAuthen fail")
				}
				sess.t.Unlock()

				//waitting for server reply
				for {
					select {
					case buffer := <-sess.ReadBuffer:
						done, err := PAPAuthenReply(sess, buffer)
						if err != nil {
							sess.close()
							fmt.Printf("authen fail,error %s\n", err.Error())
							return err
						} else if done {
							fmt.Printf("authen PAP success\n")
							return nil
						}
					case <-time.After(time.Duration(sess.timeout) * time.Second):
						fmt.Printf("receive reply timeout\n")
						//关闭连接
						sess.close()
						return errors.New("timeout")
					case <-sess.ctx.Done():
						fmt.Printf("sess close")
						sess.close()
						return errors.New("session close")
					}
				}
			}
		}
	}
}

func PAPAuthenStart(sess *Session) ([]byte, error) {
	sess.Lock()
	defer sess.Unlock()

	packet := &AuthenStart{}
	packet.Header.Version = (MajorVersion | MinorVersionOne)
	packet.Header.Type = TypeAuthen
	packet.Header.SeqNo = sess.SessionSeqNo
	sess.SessionSeqNo++
	if sess.mng.Config.ConnMultiplexing {
		packet.Header.Flags |= SingleConnectFlag
	}
	packet.Header.SessionID = sess.SessionID
	packet.Action = AuthenActionLogin
	packet.PrivLvl = PrivLvlRoot
	packet.AuthenType = AuthenTypePAP
	packet.Service = AuthenServiceLogin

	totalLen := 8
	packet.UserLen = uint8(len(sess.UserName))
	packet.User = sess.UserName
	totalLen += int(packet.UserLen)
	//fmt.Printf("userLen:%d\n", int(packet.UserLen))

	port, err := GetPort(sess.t.netConn.nc.LocalAddr().String())
	if err != nil {
		fmt.Printf("GetPort Fail:%s\n", err.Error())
	} else {
		packet.Port = strconv.FormatUint(uint64(port), 16)
		//fmt.Printf("LocalPort : %d\n", port)
	}
	packet.PortLen = uint8(len(packet.Port))
	//fmt.Printf("portLen:%d\n", int(len(packet.Port)))
	totalLen += int(packet.PortLen)

	addr, err := GetIP(sess.t.netConn.nc.LocalAddr().String())
	if err != nil {
		fmt.Printf("GetIP fail,%s\n", err.Error())
		packet.RmtAddrLen = 0
	} else {
		packet.RmtAddr = addr
		packet.RmtAddrLen = uint8(len(addr))
	}
	//fmt.Printf("addr:%d\n", int(len(addr)))
	totalLen += int(packet.RmtAddrLen)

	packet.DataLen = uint8(len(sess.Password))
	packet.Data = sess.Password
	totalLen += int(packet.DataLen)

	packet.Header.Length = uint32(totalLen)
	//fmt.Printf("total len :%d\n", totalLen)

	data, err := packet.marshal()
	if err != nil {
		fmt.Printf("packet marshal fail, error msg :%s\n", err.Error())
		return nil, err
	} else {
		//fmt.Printf("total byte :%d\n", len(data))
		crypt(data, []byte(sess.mng.Config.ShareKey))
		return data, nil
	}
}

func PAPAuthenReply(sess *Session, buffer []byte) (bool, error) {
	reply := &AuthenReplyPacket{}
	(&(reply.Header)).unmarshal(buffer)

	err := reply.varify(sess)
	if err != nil {
		fmt.Printf("%s\n", err.Error())
		return false, err
	}
	//解密
	crypt(buffer, []byte(sess.mng.Config.ShareKey))

	body := buffer[HeaderLen:]
	reply.unmarshal(body)

	switch reply.Status {
	case AuthenStatusPass:
		fmt.Printf("server reply pass\n")
		return true, nil

	case AuthenStatusFail:
		fmt.Printf("server reply fail\n")
		return false, errors.New("server reply fail")

	case AuthenStatusGetData:
		fmt.Printf("server reply getdata\n")
		return false, errors.New("unsupported option,server reply getdata")

	case AuthenStatusGetUser:
		fmt.Printf("server reply getuser\n")
		return false, errors.New("unsupported option,server reply getuser")

	case AuthenStatusGetPass:
		fmt.Printf("server reply getpass\n")
		return false, errors.New("unsupported option,server reply getPass")

	case AuthenStatusRestart:
		fmt.Printf("server reply restart\n")
		return false, errors.New("unsupported option,server reply restart")

	case AuthenStatusError:
		fmt.Printf("server reply error\n")
		return false, errors.New("server reply error")

	case AuthenStatusFollow:
		fmt.Printf("server reply follow\n")
		return false, errors.New("unsupported option,server reply follow")

	default:
		fmt.Printf("server reply unrecognized,%d\n", reply.Status)
		msg := fmt.Sprint("%s %d", "server reply unrecognized", reply.Status)
		return false, errors.New(msg)
	}
}

//5.4.2.3. CHAP login
//
//action = TAC_PLUS_AUTHEN_LOGIN
//authen_type = TAC_PLUS_AUTHEN_TYPE_CHAP
//minor_version = 0x1
//
//The entire exchange MUST consist of a single START packet and a
//single REPLY. The START packet MUST contain the username in the user
//field and the data field is a concatenation of the PPP id, the
//challenge and the response.
//The length of the challenge value can be determined from the length
//of the data field minus the length of the id (always 1 octet) and the
//length of the response field (always 16 octets).
//To perform the authentication, the server calculates the PPP hash as
//defined in the PPP Authentication RFC RFC 1334 [RFC1334] and then
//compare that value with the response. The MD5 algorithm option is
//always used. The REPLY from the server MUST be a PASS, FAIL or
//ERROR.
//The selection of the challenge and its length are not an aspect of
//the TACACS+ protocol. However, it is strongly recommended that the
//client/endstation interaction is configured with a secure challenge.
//The TACACS+ server can help by rejecting authentications where the
//challenge is below a minimum length (Minimum recommended is 8 bytes).
func AuthenCHAP() error {
	//TODO
	return nil
}

//5.4.2.4. MS-CHAP v1 login
//
//action = TAC_PLUS_AUTHEN_LOGIN
//authen_type = TAC_PLUS_AUTHEN_TYPE_MSCHAP
//minor_version = 0x1
//
//The entire exchange MUST consist of a single START packet and a
//single REPLY. The START packet MUST contain the username in the user
//field and the data field will be a concatenation of the PPP id, the
//MS-CHAP challenge and the MS-CHAP response.
//The length of the challenge value can be determined from the length
//of the data field minus the length of the id (always 1 octet) and the
//length of the response field (always 49 octets).
//To perform the authentication, the server will use a combination of
//MD4 and DES on the user’s secret and the challenge, as defined in RFC
//2433 [RFC2433] and then compare the resulting value with the
//response. The REPLY from the server MUST be a PASS or FAIL.
//For best practices, please refer to RFC 2433 [RFC2433] . The TACACS+
//server MUST reject authentications where the challenge deviates from
//8 bytes as defined in the RFC.
func AuthenMSCHAP() error {
	//TODO
	return nil
}

//5.4.2.5. MS-CHAP v2 login
//
//action = TAC_PLUS_AUTHEN_LOGIN
//authen_type = TAC_PLUS_AUTHEN_TYPE_MSCHAPV2
//minor_version = 0x1
//
//The entire exchange MUST consist of a single START packet and a
//single REPLY. The START packet MUST contain the username in the user
//field and the data field will be a concatenation of the PPP id, the
//MS-CHAP challenge and the MS-CHAP response.
//The length of the challenge value can be determined from the length
//of the data field minus the length of the id (always 1 octet) and the
//length of the response field (always 49 octets).
//To perform the authentication, the server will use the algorithm
//specified RFC 2759 [RFC2759] on the user’s secret and challenge and
//then compare the resulting value with the response. The REPLY from
//the server MUST be a PASS or FAIL.
//For best practices for MS-CHAP v2, please refer to RFC2759 [RFC2759]
//. The TACACS+ server MUST rejects authentications where the challenge
//deviates from 16 bytes as defined in the RFC.
func AuthenMSCHAPv2() error {
	//TODO
	return nil
}

//5.4.2.6. Enable Requests
//
//action = TAC_PLUS_AUTHEN_LOGIN
//priv_lvl = implementation dependent
//authen_type = not used
//service = TAC_PLUS_AUTHEN_SVC_ENABLE
//
//This is an ENABLE request, used to change the current running
//privilege level of a user. The exchange MAY consist of multiple
//messages while the server collects the information it requires in
//order to allow changing the principal’s privilege level. This
//exchange is very similar to an ASCII login (Section 5.4.2.1) .
//In order to readily distinguish enable requests from other types of
//request, the value of the authen_service field MUST be set to
//TAC_PLUS_AUTHEN_SVC_ENABLE when requesting an ENABLE. It MUST NOT be
//set to this value when requesting any other operation.
func AuthenEnable() error {
	//TODO
	return nil
}

//5.4.2.7. ASCII change password request
//
//action = TAC_PLUS_AUTHEN_CHPASS
//authen_type = TAC_PLUS_AUTHEN_TYPE_ASCII
//
//This exchange consists of multiple messages while the server collects
//the information it requires in order to change the user’s password.
//It is very similar to an ASCII login. The status value
//TAC_PLUS_AUTHEN_STATUS_GETPASS MUST only be used when requesting the
//"new" password. It MAY be sent multiple times. When requesting the
//"old" password, the status value MUST be set to
//TAC_PLUS_AUTHEN_STATUS_GETDATA.

func AuthenChangePassword() error {
	//TODO
	return nil
}
