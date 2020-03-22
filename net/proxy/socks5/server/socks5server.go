package socks5server

import (
	"context"
	"errors"
	"log"
	"net"
	"strconv"
	"time"
)

// Server <--
type Server struct {
	Server      string
	Port        string
	Username    string
	Password    string
	ForwardFunc func(host string) (net.Conn, error)
	context     context.Context
	cancel      context.CancelFunc
	conn        *net.TCPListener
}

// NewSocks5Server create new socks5 listener
// server: socks5 listener host
// port: socks5 listener port
// username: socks5 server username
// password: socks5 server password
// forwardTo: if you want to forward to another server,create a function that return net.Conn and use it,if not use nil
func NewSocks5Server(server, port, username, password string, forwardFunc func(host string) (net.Conn, error)) (*Server, error) {
	return &Server{
		Server:      server,
		Port:        port,
		Username:    username,
		Password:    password,
		ForwardFunc: forwardFunc,
	}, nil
}

func (s *Server) socks5AcceptARequest() error {
	client, err := s.conn.AcceptTCP()
	if err != nil {
		return err
	}
	if err = client.SetKeepAlivePeriod(5 * time.Second); err != nil {
		return err
	}
	go func() {
		if client == nil {
			return
		}
		defer func() {
			_ = client.Close()
		}()
		if err := s.handleClientRequest(client); err != nil {
			log.Println(err)
			return
		}
	}()
	return nil
}

// Socks5 <--
func (s *Server) Socks5() error {
	s.context, s.cancel = context.WithCancel(context.Background())
	socks5ServerIP := net.ParseIP(s.Server)
	socks5ServerPort, err := strconv.Atoi(s.Port)
	if err != nil {
		return err
	}
	s.conn, err = net.ListenTCP("tcp", &net.TCPAddr{IP: socks5ServerIP, Port: socks5ServerPort})
	if err != nil {
		return err
	}
	for {
		select {
		case <-s.context.Done():
			return nil
		default:
			if err := s.socks5AcceptARequest(); err != nil {
				select {
				case <-s.context.Done():
					return err
				default:
					log.Println(err)
					continue
				}
			}
		}
	}
}

// Close close socks5 listener
func (s *Server) Close() error {
	defer func() {
		if err := recover(); err != nil {
			return
		}
	}()
	s.cancel()
	_ = s.conn.Close()
	return nil
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

		// response to connect successful
		if _, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); err != nil {
			return err
		}

		var server net.Conn
		switch b[1] {
		case 0x01:
			if s.ForwardFunc != nil {
				if server, err = s.ForwardFunc(net.JoinHostPort(host, port)); err != nil {
					return err
				}
			} else {
				if server, err = net.Dial("tcp", net.JoinHostPort(host, port)); err != nil {
					return err
				}
			}

		case 0x02:
			log.Println("bind request " + net.JoinHostPort(host, port))
			if server, err = net.Dial("tcp", net.JoinHostPort(host, port)); err != nil {
				return err
			}

		case 0x03:
			log.Println("udp request " + net.JoinHostPort(host, port))
			if server, err = net.Dial("udp", net.JoinHostPort(host, port)); err != nil {
				return err
			}
		}
		defer func() {
			_ = server.Close()
		}()
		forward(client, server)
	}
	return nil
}

func forward(src, dst net.Conn) {
	CloseSig := make(chan error, 0)
	go pipe(src, dst, CloseSig)
	go pipe(dst, src, CloseSig)
	<-CloseSig
	<-CloseSig
	close(CloseSig)
}

func pipe(src, dst net.Conn, closeSig chan error) {
	buf := make([]byte, 0x400*32)
	for {
		n, err := src.Read(buf[0:])
		if n == 0 || err != nil {
			closeSig <- err
			return
		}
		_, err = dst.Write(buf[0:n])
		if err != nil {
			closeSig <- err
			return
		}
	}
}
