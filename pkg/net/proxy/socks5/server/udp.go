package socks5server

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log/logasfmt"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
)

// https://github.com/haxii/socks5/blob/bb9bca477f9b3ca36fa3b43e3127e3128da1c15b/udp.go#L20
// https://github.com/net-byte/socks5-server/blob/main/socks5/udp.go
type udpServer struct {
	l net.PacketConn
	p net.PacketConn

	target net.Addr
	local  net.Addr

	header []byte
}

func newUDPServer(f proxy.Proxy, target string) (*udpServer, error) {
	l, err := net.ListenPacket("udp", "")
	if err != nil {
		return nil, fmt.Errorf("listen udp failed: %v", err)
	}

	p, err := f.PacketConn(target)
	if err != nil {
		return nil, fmt.Errorf("connect to %s failed: %v", target, err)
	}

	tar, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return nil, fmt.Errorf("resolve udp addr failed: %v", err)
	}

	u := &udpServer{l: l, p: p, target: tar}
	go u.l2r()
	return u, nil
}

func (u *udpServer) l2r() {
	buf := make([]byte, 1024)
	for {
		n, l, err := u.l.ReadFrom(buf)
		if err != nil {
			break
		}

		_, _, size, err := ResolveAddr(buf[3:n])
		if err != nil {
			logasfmt.Println("resolve addr failed:", err)
			continue
		}

		if u.header == nil {
			u.local = l
			u.header = make([]byte, 3+size)
			copy(u.header, buf[:3+size])
			go u.r2l()
		}

		u.p.WriteTo(buf[3+size:n], u.target)
	}
}

func (u *udpServer) r2l() {
	buf := make([]byte, 1024)
	for {
		n, _, err := u.p.ReadFrom(buf)
		if err != nil {
			break
		}

		u.l.SetWriteDeadline(time.Now().Add(time.Second * 30))
		u.l.WriteTo(append(u.header, buf[:n]...), u.local)
	}
}

func (u *udpServer) Close() {
	if u.l != nil {
		u.l.Close()
	}

	if u.p != nil {
		u.p.Close()
	}
}

var _ net.PacketConn = (*udpHandlerPacketConn)(nil)

type udpHandlerPacketConn struct {
	net.PacketConn
	key string
	m   *sync.Map
}

func (u *udpHandlerPacketConn) Close() error {
	u.m.Delete(u.key)
	return u.PacketConn.Close()
}
