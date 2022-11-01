package socks5server

import (
	"fmt"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	iserver "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/server"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
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

func handshake(dialer proxy.Proxy, username, password string) func(net.Conn) {
	return func(conn net.Conn) {

		if err := handle(username, password, conn, dialer); err != nil {
			log.Errorln("socks5 server handle failed:", err)
		}
	}
}

func handle(user, key string, client net.Conn, f proxy.Proxy) (err error) {
	b := pool.GetBytes(pool.DefaultSize)
	defer pool.PutBytes(b)

	err = handshake1(client, user, key, b)
	if err != nil {
		return fmt.Errorf("first hand failed: %w", err)
	}

	if err = handshake2(client, f, b); err != nil {
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
		var addr proxy.Address
		addr, _, err = s5c.ResolveAddr("tcp", client)
		if err != nil {
			return fmt.Errorf("resolve addr failed: %w", err)
		}
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
	l, err := newUDPServer(f)
	if err != nil {
		return fmt.Errorf("new udp server failed: %w", err)
	}
	laddr, err := proxy.ParseSysAddr(l.LocalAddr())
	if err != nil {
		return fmt.Errorf("parse sys addr failed: %w", err)
	}
	writeHandshake2(client, succeeded, proxy.ParseAddressSplit("udp", "0.0.0.0", laddr.Port()))
	relay.Copy(io.Discard, client)
	return l.Close()
}

func writeHandshake1(conn net.Conn, errREP byte) error {
	_, err := conn.Write([]byte{0x05, errREP})
	return err
}

func writeHandshake2(conn net.Conn, errREP byte, addr proxy.Address) error {
	_, err := conn.Write(append([]byte{0x05, errREP, 0x00}, s5c.ParseAddr(addr)...))
	return err
}

func NewServer(o *listener.Opts[*listener.Protocol_Socks5]) (iserver.Server, error) {
	x := o.Protocol.Socks5
	return server.NewTCPServer(x.Host, handshake(o.Dialer, x.Username, x.Password))
}
