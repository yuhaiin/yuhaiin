package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	iserver "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
)

const (
	noAuthenticationRequired = 0x00
	gssapi                   = 0x01
	userAndPassword          = 0x02
	noAcceptableMethods      = 0xff

	succeeded                     = 0x00
	socksServerFailure            = 0x01
	connectionNotAllowedByRuleset = 0x02
	networkUnreachable            = 0x03
	hostUnreachable               = 0x04
	connectionRefused             = 0x05
	ttlExpired                    = 0x06
	commandNotSupport             = 0x07
	addressTypeNotSupport         = 0x08
)

func (s *Socks5) newTCPServer() error {
	lis, err := dialer.ListenContext(context.TODO(), "tcp", s.addr)
	if err != nil {
		return err
	}

	s.lis = lis

	go func() {
		defer s.Close()
		for {
			conn, err := lis.Accept()
			if err != nil {
				log.Errorln("accept failed:", err)
				if ne, ok := err.(net.Error); ok && ne.Temporary() {
					continue
				}
				return
			}

			go func() {
				defer conn.Close()
				if err := s.handle(conn); err != nil {
					if errors.Is(err, proxy.ErrBlocked) {
						log.Debugln(err)
					} else {
						log.Errorln("socks5 server handle failed:", err)
					}
				}
			}()

		}
	}()

	return nil
}

func (s *Socks5) handle(client net.Conn) (err error) {
	b := pool.GetBytes(pool.DefaultSize)
	defer pool.PutBytes(b)

	err = handshake1(client, s.username, s.password, b)
	if err != nil {
		return fmt.Errorf("first hand failed: %w", err)
	}

	if err = handshake2(client, s.dialer, b); err != nil {
		return fmt.Errorf("second hand failed: %w", err)
	}

	return
}

func handshake1(client net.Conn, user, key string, buf []byte) error {
	//socks5 first handshake
	if _, err := io.ReadFull(client, buf[:3]); err != nil {
		return fmt.Errorf("read first handshake failed: %w", err)
	}

	if buf[0] != 0x05 { // ver
		writeHandshake1(client, noAcceptableMethods)
	}

	if buf[2] == noAuthenticationRequired { // method
		return writeHandshake1(client, noAuthenticationRequired)
	}

	if buf[1] == 1 && buf[2] == userAndPassword { // nMethod
		return verifyUserPass(client, user, key)
	}
	writeHandshake1(client, noAcceptableMethods)
	return fmt.Errorf("no Acceptable Methods: length:%d, method:%d, from:%s", buf[1], buf[2], client.RemoteAddr())
}

func verifyUserPass(client net.Conn, user, key string) error {
	b := pool.GetBytes(pool.DefaultSize)
	defer pool.PutBytes(b)
	// get username and password
	_, err := client.Read(b[:])
	if err != nil {
		return err
	}
	username := b[2 : 2+b[1]]
	password := b[3+b[1] : 3+b[1]+b[2+b[1]]]
	if user != string(username) || key != string(password) {
		writeHandshake1(client, 0x01)
		return fmt.Errorf("verify username and password failed")
	}
	writeHandshake1(client, 0x00)
	return nil
}

func handshake2(client net.Conn, f proxy.Proxy, buf []byte) error {
	// socks5 second handshake
	if _, err := io.ReadFull(client, buf[:3]); err != nil {
		return fmt.Errorf("read second handshake failed: %w", err)
	}

	if buf[0] != 0x05 { // ver
		writeHandshake2(client, noAcceptableMethods, proxy.EmptyAddr)
	}

	var err error

	switch s5c.CMD(buf[1]) { // mode
	case s5c.Connect:
		var adr s5c.ADDR
		adr, err = s5c.ResolveAddr(client)
		if err != nil {
			return fmt.Errorf("resolve addr failed: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.TODO(), time.Second*5)
		defer cancel()

		addr := adr.Address(statistic.Type_tcp)
		addr.WithContext(ctx)
		addr.WithValue(proxy.SourceKey{}, client.RemoteAddr())
		addr.WithValue(proxy.InboundKey{}, client.LocalAddr())
		addr.WithValue(proxy.DestinationKey{}, addr)

		err = handleConnect(addr, client, f)

	case s5c.Udp: // udp
		err = handleUDP(client, f)

	case s5c.Bind: // bind request
		fallthrough

	default:
		writeHandshake2(client, commandNotSupport, proxy.EmptyAddr)
		return fmt.Errorf("not Support Method %d", buf[1])
	}

	if err != nil {
		writeHandshake2(client, hostUnreachable, proxy.EmptyAddr)
	}
	return err
}

func handleConnect(target proxy.Address, client net.Conn, f proxy.Proxy) error {
	server, err := f.Conn(target)
	if err != nil {
		return fmt.Errorf("connect to %s failed: %w", target, err)
	}
	caddr, err := proxy.ParseSysAddr(client.LocalAddr())
	if err != nil {
		return fmt.Errorf("parse local addr failed: %w", err)
	}
	writeHandshake2(client, succeeded, caddr) // response to connect successful
	// hand shake successful
	relay.Relay(client, server)
	server.Close()
	return nil
}

func handleUDP(client net.Conn, f proxy.Proxy) error {
	laddr, err := proxy.ParseSysAddr(client.LocalAddr())
	if err != nil {
		return fmt.Errorf("parse sys addr failed: %w", err)
	}
	writeHandshake2(client, succeeded, proxy.ParseAddressPort(statistic.Type_tcp, "0.0.0.0", laddr.Port()))
	relay.Copy(io.Discard, client)
	return nil
}

func writeHandshake1(conn net.Conn, errREP byte) error {
	_, err := conn.Write([]byte{0x05, errREP})
	return err
}

func writeHandshake2(conn net.Conn, errREP byte, addr proxy.Address) error {
	_, err := conn.Write(append([]byte{0x05, errREP, 0x00}, s5c.ParseAddr(addr)...))
	return err
}

type Socks5 struct {
	udpServer *udpServer
	lis       net.Listener

	dialer   proxy.Proxy
	addr     string
	username string
	password string
}

func (s *Socks5) Close() error {
	var err error

	if s.udpServer != nil {
		if er := s.udpServer.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}

	if s.lis != nil {
		if er := s.lis.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}

	return err
}

func NewServer(o *listener.Opts[*listener.Protocol_Socks5]) (iserver.Server, error) {
	s := &Socks5{
		dialer:   o.Dialer,
		addr:     o.Protocol.Socks5.Host,
		username: o.Protocol.Socks5.Username,
		password: o.Protocol.Socks5.Password,
	}

	err := s.newUDPServer()
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("new udp server failed: %w", err)
	}

	err = s.newTCPServer()
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("new tcp server failed: %w", err)
	}

	return s, nil
}
