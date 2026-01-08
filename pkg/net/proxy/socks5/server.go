package socks5

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya"
	"github.com/Asutorufa/yuhaiin/pkg/net/relay"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

func (s *Server) startUDPServer() error {
	packet, err := s.lis.Packet(s.ctx)
	if err != nil {
		return err
	}

	go func() {
		defer packet.Close()
		err := (&yuubinsya.UDPServer{
			PacketConn: packet,
			Handler:    s.handler.HandlePacket,
			Prefix:     true,
		}).Serve()
		if err != nil {
			log.Error("start udp server failed", "err", err)
		}
	}()

	return nil
}

func (s *Server) startTCPServer() error {
	go func() {
		defer s.Close()

		sl := netapi.NewErrCountListener(s.lis, 10)

		for {
			conn, err := sl.Accept()
			if err != nil {
				log.Error("socks5 accept failed", "err", err)

				if ne, ok := err.(net.Error); ok && ne.Temporary() {
					continue
				}
				return
			}

			go func() {
				if err := s.Handle(conn); err != nil {
					log.Error("socks5 tcp server handle", "msg", err)
				}
			}()

		}
	}()

	return nil
}

func (s *Server) Handle(client net.Conn) (err error) {
	b := pool.GetBytes(pool.DefaultSize)
	defer pool.PutBytes(b)

	err = s.handshake1(client, b)
	if err != nil {
		return fmt.Errorf("first hand failed: %w", err)
	}

	if err = s.handshake2(client, b); err != nil {
		return fmt.Errorf("second hand failed: %w", err)
	}

	return
}

func (s *Server) handshake1(client net.Conn, buf []byte) error {
	//socks5 first handshake
	if _, err := io.ReadFull(client, buf[:2]); err != nil {
		return fmt.Errorf("read first handshake failed: %w", err)
	}

	if buf[0] != 0x05 { // ver
		err := writeHandshake1(client, tools.NoAcceptableMethods)
		return fmt.Errorf("no acceptable method: %d, resp err: %w", buf[0], err)
	}

	nMethods := int(buf[1])

	if nMethods > len(buf) {
		err := writeHandshake1(client, tools.NoAcceptableMethods)
		return fmt.Errorf("nMethods length of methods out of buf, resp err: %w", err)
	}

	if _, err := io.ReadFull(client, buf[:nMethods]); err != nil {
		return fmt.Errorf("read methods failed: %w", err)
	}

	noNeedVerify := s.username == "" && s.password == ""
	userAndPasswordSupport := false

	for _, v := range buf[:nMethods] { // range all supported methods
		if v == tools.NoAuthenticationRequired && noNeedVerify {
			return writeHandshake1(client, tools.NoAuthenticationRequired)
		}

		if v == tools.UserAndPassword {
			userAndPasswordSupport = true
		}
	}

	if userAndPasswordSupport {
		return verifyUserPass(client, s.username, s.password)
	}

	err := writeHandshake1(client, tools.NoAcceptableMethods)

	return fmt.Errorf("no acceptable authentication methods: [length: %d, method:%v], response err: %w", nMethods, buf[:nMethods], err)
}

func verifyUserPass(client net.Conn, user, key string) error {
	if err := writeHandshake1(client, tools.UserAndPassword); err != nil {
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

	if (len(user) > 0 && subtle.ConstantTimeCompare([]byte(user), username) != 1) ||
		(len(key) > 0 && subtle.ConstantTimeCompare([]byte(key), password) != 1) {
		_, err := client.Write([]byte{1, 1})
		return fmt.Errorf("verify username and password failed, resp err: %w", err)
	}

	_, err := client.Write([]byte{1, 0})
	return err
}

func (s *Server) handshake2(client net.Conn, buf []byte) error {
	// socks5 second handshake
	if _, err := io.ReadFull(client, buf[:3]); err != nil {
		return fmt.Errorf("read second handshake failed: %w", err)
	}

	if buf[0] != 0x05 { // ver
		err := writeHandshake2(client, tools.NoAcceptableMethods, netapi.EmptyAddr)
		return fmt.Errorf("no acceptable method: %d, resp err: %w", buf[0], err)
	}

	var err error

	switch tools.CMD(buf[1]) { // mode
	case tools.Connect:
		var adr tools.Addr
		adr, err = tools.ResolveAddr(client)
		if err != nil {
			return fmt.Errorf("resolve addr failed: %w", err)
		}
		defer pool.PutBytes(adr)

		addr := adr.Address("tcp")

		caddr, err := netapi.ParseSysAddr(client.LocalAddr())
		if err != nil {
			return fmt.Errorf("parse local addr failed: %w", err)
		}
		err = writeHandshake2(client, tools.Succeeded, caddr) // response to connect successful
		if err != nil {
			return err
		}

		s.handler.HandleStream(&netapi.StreamMeta{
			Source:      client.RemoteAddr(),
			Destination: addr,
			Inbound:     client.LocalAddr(),
			Src:         client,
			Address:     addr,
		})
		return nil

	case tools.Ping:
		var adr tools.Addr
		adr, err = tools.ResolveAddr(client)
		if err != nil {
			return fmt.Errorf("resolve addr failed: %w", err)
		}
		defer pool.PutBytes(adr)

		addr := adr.Address("udp")

		caddr, err := netapi.ParseSysAddr(client.LocalAddr())
		if err != nil {
			return fmt.Errorf("parse local addr failed: %w", err)
		}

		s.handler.HandlePing(&netapi.PingMeta{
			Source:      client.RemoteAddr(),
			Destination: addr,
			WriteBack: func(u uint64, err error) error {
				if err != nil {
					return writeHandshake2(client, tools.HostUnreachable, caddr)
				}
				return writeHandshake2(client, tools.Succeeded, caddr)
			},
		})
		return nil

	case tools.Udp: // udp
		if s.udp {
			err = handleUDP(client)
			break
		}
		fallthrough

	case tools.Bind: // bind request
		fallthrough

	default:
		_ = writeHandshake2(client, tools.CommandNotSupport, netapi.EmptyAddr)
		return fmt.Errorf("not support method: %d", buf[1])
	}

	if err != nil {
		_ = writeHandshake2(client, tools.HostUnreachable, netapi.EmptyAddr)
	}
	return err
}

func handleUDP(client net.Conn) error {
	laddr, err := netapi.ParseSysAddr(client.LocalAddr())
	if err != nil {
		return fmt.Errorf("parse sys addr failed: %w", err)
	}

	addr, err := netapi.ParseAddressPort("tcp", "0.0.0.0", uint16(laddr.Port()))
	if err != nil {
		return fmt.Errorf("parse laddr failed: %w", err)
	}

	err = writeHandshake2(client, tools.Succeeded, addr)
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
	adr := tools.ParseAddr(addr)
	defer pool.PutBytes(adr)
	_, err := conn.Write(append([]byte{0x05, errREP, 0x00}, adr...))
	return err
}

type Server struct {
	netapi.EmptyInterface
	lis netapi.Listener

	handler netapi.Handler
	ctx     context.Context
	cancel  context.CancelFunc

	username string
	password string
	udp      bool
}

func (s *Server) Close() error {
	s.cancel()
	return s.lis.Close()
}

func init() {
	register.RegisterProtocol(NewServer)
}

func NewServer(o *config.Socks5, ii netapi.Listener, handler netapi.Handler) (netapi.Accepter, error) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		udp:      o.GetUdp(),
		username: o.GetUsername(),
		password: o.GetPassword(),
		lis:      ii,
		handler:  handler,
		ctx:      ctx,
		cancel:   cancel,
	}

	if s.udp {
		if err := s.startUDPServer(); err != nil {
			return nil, err
		}
	}

	if err := s.startTCPServer(); err != nil {
		s.Close()
		return nil, err
	}

	return s, nil
}
