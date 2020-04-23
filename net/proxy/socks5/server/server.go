package socks5server

import (
	"errors"
	"github.com/Asutorufa/yuhaiin/net/common"
	"log"
	"net"
	"strconv"
	"time"
)

// Server <--
type Server struct {
	Username string
	Password string
	listener net.Listener
	closed   bool
}

// NewSocks5Server create new socks5 listener
// server: socks5 listener host
// port: socks5 listener port
// username: socks5 server username
// password: socks5 server password
func NewSocks5Server(host, port, username, password string) (*Server, error) {
	var err error
	s := &Server{}
	s.listener, err = net.Listen("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	s.Username, s.Password = username, password
	go func() {
		if err := s.Socks5(); err != nil {
			log.Print(err)
			return
		}
	}()
	return s, nil
}

func (s *Server) UpdateListen(host, port string) (err error) {
	if s.listener.Addr().String() == net.JoinHostPort(host, port) {
		return nil
	}
	if err = s.listener.Close(); err != nil {
		return err
	}
	s.listener, err = net.Listen("tcp", net.JoinHostPort(host, port))
	return
}

func (s *Server) GetListenHost() string {
	return s.listener.Addr().String()
}

// Socks5 <--
func (s *Server) Socks5() error {
	for {
		client, err := s.listener.Accept()
		if err != nil {
			if s.closed {
				break
			}
			continue
		}
		if err := client.(*net.TCPConn).SetKeepAlive(true); err != nil {
			return err
		}
		go func() {
			defer func() {
				_ = client.Close()
			}()
			if err := s.handleClientRequest(client); err != nil {
				//log.Println(err)
				return
			}
		}()
	}
	return nil
}

// Close close socks5 listener
func (s *Server) Close() error {
	s.closed = true
	return s.listener.Close()
}

func (s *Server) handleClientRequest(client net.Conn) error {
	var b [1024]byte
	_, err := client.Read(b[:])
	if err != nil {
		return err
	}

	if b[0] == 0x05 { //只处理Socks5协议
		_, _ = client.Write([]byte{0x05, 0x00})
		if b[1] == 0x01 {
			// 对用户名密码进行判断
			if b[2] == 0x02 {
				_, err = client.Read(b[:])
				if err != nil {
					return err
				}
				username := b[2 : 2+b[1]]
				password := b[3+b[1] : 3+b[1]+b[2+b[1]]]
				if s.Username == string(username) && s.Password == string(password) {
					_, _ = client.Write([]byte{0x01, 0x00})
				} else {
					_, _ = client.Write([]byte{0x01, 0x01})
					return errors.New("username or password not correct")
				}
			}
		}

		n, err := client.Read(b[:])
		if err != nil {
			return err
		}

		var host, port string
		switch b[3] {
		case 0x01: //IP V4
			host = net.IPv4(b[4], b[5], b[6], b[7]).String()
		case 0x03: //域名
			host = string(b[5 : n-2]) //b[4]表示域名的长度
		case 0x04: //IP V6
			host = net.IP{b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19]}.String()
		}
		port = strconv.Itoa(int(b[n-2])<<8 | int(b[n-1]))

		var server net.Conn
		switch b[1] {
		case 0x01:
			if common.ForwardTarget != nil {
				if server, err = common.ForwardTarget(net.JoinHostPort(host, port)); err != nil {
					_, err = client.Write([]byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
					return err
				}
			} else {
				if server, err = net.DialTimeout("tcp", net.JoinHostPort(host, port), 5*time.Second); err != nil {
					_, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
					return err
				}
			}

		case 0x02: // bind request
			if server, err = net.Dial("tcp", net.JoinHostPort(host, port)); err != nil {
				_, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
				return err
			}

		case 0x03: // udp request
			if server, err = net.Dial("udp", net.JoinHostPort(host, port)); err != nil {
				_, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
				return err
			}
		}
		// response to connect successful
		if _, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); err != nil {
			return err
		}
		defer func() {
			_ = server.Close()
		}()
		common.Forward(client, server)
	}
	return nil
}
