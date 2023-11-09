package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
)

func (s *Socks5) newTCPServer(lis net.Listener) {
	s.lis = lis

	go func() {
		defer s.Close()
		for {
			conn, err := lis.Accept()
			if err != nil {
				log.Error("socks5 accept failed", "err", err)

				if ne, ok := err.(net.Error); ok && ne.Temporary() {
					continue
				}
				return
			}

			go func() {
				if err := s.handle(conn); err != nil {
					if errors.Is(err, netapi.ErrBlocked) {
						log.Debug(err.Error())
					} else {
						log.Error("socks5 server handle failed", "err", err)
					}
				}
			}()

		}
	}()
}

func (s *Socks5) handle(client net.Conn) (err error) {
	b := pool.GetBytes(pool.DefaultSize)
	defer pool.PutBytes(b)

	err = handshake1(client, s.username, s.password, b)
	if err != nil {
		return fmt.Errorf("first hand failed: %w", err)
	}

	if err = handshake2(client, s.handler, b, s.UDP); err != nil {
		return fmt.Errorf("second hand failed: %w", err)
	}

	return
}

func handshake1(client net.Conn, user, key string, buf []byte) error {
	//socks5 first handshake
	if _, err := io.ReadFull(client, buf[:2]); err != nil {
		return fmt.Errorf("read first handshake failed: %w", err)
	}

	if buf[0] != 0x05 { // ver
		err := writeHandshake1(client, s5c.NoAcceptableMethods)
		return fmt.Errorf("no acceptable method: %d, resp err: %w", buf[0], err)
	}

	nMethods := int(buf[1])

	if nMethods > len(buf) {
		err := writeHandshake1(client, s5c.NoAcceptableMethods)
		return fmt.Errorf("nMethods length of methods out of buf, resp err: %w", err)
	}

	if _, err := io.ReadFull(client, buf[:nMethods]); err != nil {
		return fmt.Errorf("read methods failed: %w", err)
	}

	noNeedVerify := user == "" && key == ""
	userAndPasswordSupport := false

	for _, v := range buf[:nMethods] { // range all supported methods
		if v == s5c.NoAuthenticationRequired && noNeedVerify {
			return writeHandshake1(client, s5c.NoAuthenticationRequired)
		}

		if v == s5c.UserAndPassword {
			userAndPasswordSupport = true
		}
	}

	if userAndPasswordSupport {
		return verifyUserPass(client, user, key)
	}

	err := writeHandshake1(client, s5c.NoAcceptableMethods)

	return fmt.Errorf("no acceptable authentication methods: [length: %d, method:%v], response err: %w", nMethods, buf[:nMethods], err)
}

func verifyUserPass(client net.Conn, user, key string) error {
	if err := writeHandshake1(client, s5c.UserAndPassword); err != nil {
		return err
	}

	b := pool.GetBytes(pool.DefaultSize)
	defer pool.PutBytes(b)

	if _, err := io.ReadFull(client, b[:2]); err != nil {
		return fmt.Errorf("read ver and user name length failed: %w", err)
	}

	// if b[0] != 0x01 {
	// 	return fmt.Errorf("unknown ver: %d", b[0])
	// }

	usernameLength := int(b[1])

	if _, err := io.ReadFull(client, b[2:2+usernameLength]); err != nil {
		return fmt.Errorf("read username failed: %w", err)
	}

	username := b[2 : 2+usernameLength]

	if _, err := io.ReadFull(client, b[2+usernameLength:2+usernameLength+1]); err != nil {
		return fmt.Errorf("read password length failed: %w", err)
	}

	passwordLength := int(b[2+usernameLength])

	if _, err := io.ReadFull(client, b[2+usernameLength+1:2+usernameLength+1+passwordLength]); err != nil {
		return fmt.Errorf("read password failed: %w", err)
	}

	password := b[2+usernameLength+1 : 2+usernameLength+1+passwordLength]

	if (len(user) > 0 && (usernameLength <= 0 || user != unsafe.String(&username[0], usernameLength))) ||
		(len(key) > 0 && (passwordLength <= 0 || key != unsafe.String(&password[0], passwordLength))) {
		_, err := client.Write([]byte{1, 1})
		return fmt.Errorf("verify username and password failed, resp err: %w", err)
	}

	_, err := client.Write([]byte{1, 0})
	return err
}

func handshake2(client net.Conn, f netapi.Handler, buf []byte, udp bool) error {
	// socks5 second handshake
	if _, err := io.ReadFull(client, buf[:3]); err != nil {
		return fmt.Errorf("read second handshake failed: %w", err)
	}

	if buf[0] != 0x05 { // ver
		err := writeHandshake2(client, s5c.NoAcceptableMethods, netapi.EmptyAddr)
		return fmt.Errorf("no acceptable method: %d, resp err: %w", buf[0], err)
	}

	var err error

	switch s5c.CMD(buf[1]) { // mode
	case s5c.Connect:
		var adr s5c.ADDR
		adr, err = s5c.ResolveAddr(client)
		if err != nil {
			return fmt.Errorf("resolve addr failed: %w", err)
		}

		addr := adr.Address(statistic.Type_tcp)

		caddr, err := netapi.ParseSysAddr(client.LocalAddr())
		if err != nil {
			return fmt.Errorf("parse local addr failed: %w", err)
		}
		err = writeHandshake2(client, s5c.Succeeded, caddr) // response to connect successful
		if err != nil {
			return err
		}

		f.Stream(context.TODO(), &netapi.StreamMeta{
			Source:      client.RemoteAddr(),
			Destination: addr,
			Inbound:     client.LocalAddr(),
			Src:         client,
			Address:     addr,
		})

	case s5c.Udp: // udp
		if udp {
			err = handleUDP(client)
			break
		}
		fallthrough

	case s5c.Bind: // bind request
		fallthrough

	default:
		err := writeHandshake2(client, s5c.CommandNotSupport, netapi.EmptyAddr)
		return fmt.Errorf("not Support Method %d, resp err: %w", buf[1], err)
	}

	if err != nil {
		_ = writeHandshake2(client, s5c.HostUnreachable, netapi.EmptyAddr)
	}
	return err
}

func handleUDP(client net.Conn) error {
	laddr, err := netapi.ParseSysAddr(client.LocalAddr())
	if err != nil {
		return fmt.Errorf("parse sys addr failed: %w", err)
	}
	err = writeHandshake2(client, s5c.Succeeded, netapi.ParseAddressPort(statistic.Type_tcp, "0.0.0.0", laddr.Port()))
	if err != nil {
		return err
	}
	_, _ = relay.Copy(io.Discard, client)
	return nil
}

func writeHandshake1(conn net.Conn, errREP byte) error {
	_, err := conn.Write([]byte{0x05, errREP})
	return err
}

func writeHandshake2(conn net.Conn, errREP byte, addr netapi.Address) error {
	_, err := conn.Write(append([]byte{0x05, errREP, 0x00}, s5c.ParseAddr(addr)...))
	return err
}

type Socks5 struct {
	UDP       bool
	udpServer *udpServer
	lis       net.Listener

	handler  netapi.Handler
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

func NewServerWithListener(lis net.Listener, o *listener.Opts[*listener.Protocol_Socks5], udp bool) (netapi.Server, error) {
	s := &Socks5{
		UDP:      udp,
		handler:  o.Handler,
		addr:     o.Protocol.Socks5.Host,
		username: o.Protocol.Socks5.Username,
		password: o.Protocol.Socks5.Password,
	}

	if udp {
		err := s.newUDPServer(o.Handler)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("new udp server failed: %w", err)
		}
	}

	s.newTCPServer(lis)

	return s, nil
}

func NewServer(o *listener.Opts[*listener.Protocol_Socks5], udp bool) (netapi.Server, error) {
	lis, err := dialer.ListenContext(context.TODO(), "tcp", o.Protocol.Socks5.Host)
	if err != nil {
		return nil, err
	}

	return NewServerWithListener(lis, o, udp)
}
