package socks5server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"
)

// ServerSocks5 <--
type ServerSocks5 struct {
	Server    string
	Port      string
	Username  string
	Password  string
	ForwardTo func(host string) (net.Conn, error)
	context   context.Context
	cancel    context.CancelFunc
	conn      *net.TCPListener
}

// NewSocks5Server create new socks5 listener
// server: socks5 listener host
// port: socks5 listener port
// username: socks5 server username
// password: socks5 server password
// forwardTo: if you want to forward to another server,create a function that return net.Conn and use it,if not use nil
func NewSocks5Server(server, port, username, password string, forwardTo func(host string) (net.Conn, error)) (*ServerSocks5, error) {
	socks5Server := &ServerSocks5{
		Server:    server,
		Port:      port,
		Username:  username,
		Password:  password,
		ForwardTo: forwardTo,
	}
	socks5Server.context, socks5Server.cancel = context.WithCancel(context.Background())
	socks5ServerIP := net.ParseIP(socks5Server.Server)
	socks5ServerPort, err := strconv.Atoi(socks5Server.Port)
	if err != nil {
		return socks5Server, err
	}
	socks5Server.conn, err = net.ListenTCP("tcp", &net.TCPAddr{IP: socks5ServerIP, Port: socks5ServerPort})
	if err != nil {
		return socks5Server, err
	}
	return socks5Server, nil
}

func (socks5Server *ServerSocks5) socks5Init() error {
	socks5Server.context, socks5Server.cancel = context.WithCancel(context.Background())
	socks5ServerIP := net.ParseIP(socks5Server.Server)
	socks5ServerPort, err := strconv.Atoi(socks5Server.Port)
	if err != nil {
		return err
	}
	socks5Server.conn, err = net.ListenTCP("tcp", &net.TCPAddr{IP: socks5ServerIP, Port: socks5ServerPort})
	if err != nil {
		return err
	}
	return nil
}

func (socks5Server *ServerSocks5) socks5AcceptARequest() error {
	client, err := socks5Server.conn.AcceptTCP()
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
		if err := socks5Server.handleClientRequest(client); err != nil {
			log.Println(err)
			return
		}
	}()
	return nil
}

// Close close socks5 listener
func (socks5Server *ServerSocks5) Close() error {
	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
		}
	}()
	socks5Server.cancel()
	return socks5Server.conn.Close()
}

// Socks5 <--
func (socks5Server *ServerSocks5) Socks5() error {
	//if err := socks5Server.socks5Init(); err != nil {
	//	return err
	//}
	for {
		select {
		case <-socks5Server.context.Done():
			return nil
		default:
			if err := socks5Server.socks5AcceptARequest(); err != nil {
				select {
				case <-socks5Server.context.Done():
					return err
				default:
					log.Println(err)
					continue
				}
			}
		}
	}
}

func (socks5Server *ServerSocks5) handleClientRequest(client net.Conn) error {
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
				if socks5Server.Username == string(username) && socks5Server.Password == string(password) {
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
			if socks5Server.ForwardTo != nil {
				if server, err = socks5Server.ForwardTo(net.JoinHostPort(host, port)); err != nil {
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
