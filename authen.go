// authen.go
package tacacs

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

//创建session的时候根据配置来设置传输层
func ASCIILoginStart(sess *Session) ([]byte, error) {
	sess.Lock()
	defer sess.Unlock()

	packet := &AuthenStartPacket{}
	packet.Header.Version = (TacacsMajorVersion | TacacsMinorVersionDefault)
	packet.Header.Type = TypeAuthen
	packet.Header.SeqNo = sess.SessionSeqNo
	sess.SessionSeqNo++
	if sess.mng.Config.ConnMultiplexing {
		packet.Header.Flags |= TacacsSingleConnectFlag
	}
	packet.Header.SessionID = sess.SessionID
	packet.Action = TacacsAuthenActionLogin
	packet.PrivLvl = TacacsPrivLvlRoot
	packet.AuthenType = TacacsAuthenTypeASCII
	packet.Service = TacacsAuthenServiceLogin

	totalLen := 8
	packet.UserLen = uint8(len(sess.UserName))
	packet.User = sess.UserName
	totalLen += int(packet.UserLen)
	fmt.Printf("userLen:%d\n", int(packet.UserLen))

	port, err := GetPort(sess.t.netConn.nc.LocalAddr().String())
	if err != nil {
		fmt.Printf("GetPort Fail:%s\n", err.Error())
	} else {
		packet.Port = strconv.FormatUint(uint64(port), 16)
		fmt.Printf("LocalPort : %d\n", port)
	}
	packet.PortLen = uint8(len(packet.Port))
	fmt.Printf("portLen:%d\n", int(len(packet.Port)))
	totalLen += int(packet.PortLen)

	addr, err := GetIP(sess.t.netConn.nc.LocalAddr().String())
	if err != nil {
		fmt.Printf("GetIP fail,%s\n", err.Error())
		packet.RmtAddrLen = 0
	} else {
		packet.RmtAddr = addr
		packet.RmtAddrLen = uint8(len(addr))
	}
	fmt.Printf("addr:%d\n", int(len(addr)))
	totalLen += int(packet.RmtAddrLen)

	packet.DataLen = 0
	packet.Header.Length = uint32(totalLen)
	fmt.Printf("total len :%d\n", totalLen)

	data, err := packet.marshal()
	if err != nil {
		fmt.Printf("packet marshal fail, error msg :%s\n", err.Error())
		return nil, err
	} else {
		fmt.Printf("total byte :%d\n", len(data))
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
	case TacacsAuthenStatusPass:
		fmt.Printf("server reply pass\n")
		return true, nil

	case TacacsAuthenStatusFail:
		fmt.Printf("server reply fail\n")
		return false, errors.New("server reply fail")

	case TacacsAuthenStatusGetData:
		fmt.Printf("server reply getdata\n")
		return false, errors.New("unsupported option,server reply getdata")

	case TacacsAuthenStatusGetUser:
		fmt.Printf("server reply getuser\n")
		return false, errors.New("unsupported option,server reply getuser")

	case TacacsAuthenStatusGetPass:
		fmt.Printf("server reply getpass\n")
		return false, ASCIILoginContinue(sess)

	case TacacsAuthenStatusRestart:
		fmt.Printf("server reply restart\n")
		return false, errors.New("unsupported option,server reply restart")

	case TacacsAuthenStatusError:
		fmt.Printf("server reply error\n")
		return false, errors.New("server reply error")

	case TacacsAuthenStatusFollow:
		fmt.Printf("server reply follow\n")
		return false, errors.New("unsupported option,server reply follow")

	default:
		fmt.Printf("server reply unrecognized,%d\n", reply.Status)
		msg := fmt.Sprint("%s %d", "server reply unrecognized", reply.Status)
		return false, errors.New(msg)
	}
}

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
