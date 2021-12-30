package socks5server

import (
	"fmt"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log/logasfmt"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	socks5client "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
)

// https://github.com/haxii/socks5/blob/bb9bca477f9b3ca36fa3b43e3127e3128da1c15b/udp.go#L20
// https://github.com/net-byte/socks5-server/blob/main/socks5/udp.go
type udpServer struct {
	listener net.PacketConn
	proxy    net.PacketConn

	remoteTarget net.Addr
	localRemote  net.Addr

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

	u := &udpServer{listener: l, proxy: p, remoteTarget: tar}
	go u.forward()
	return u, nil
}

func (u *udpServer) forward() {
	buf := make([]byte, 1024)
	for {
		n, l, err := u.listener.ReadFrom(buf)
		if err != nil {
			break
		}

		_, _, size, err := socks5client.ResolveAddr(buf[3:n])
		if err != nil {
			logasfmt.Println("resolve addr failed:", err)
			continue
		}

		if u.header == nil {
			u.localRemote = l
			u.header = make([]byte, 3+size)
			copy(u.header, buf[:3+size])
			go u.reply()
		}

		u.proxy.WriteTo(buf[3+size:n], u.remoteTarget)
	}
}

func (u *udpServer) reply() {
	buf := make([]byte, 1024)
	for {
		n, _, err := u.proxy.ReadFrom(buf)
		if err != nil {
			break
		}

		u.listener.SetWriteDeadline(time.Now().Add(time.Second * 30))
		u.listener.WriteTo(append(u.header, buf[:n]...), u.localRemote)
	}
}

func (u *udpServer) Close() {
	if u.listener != nil {
		u.listener.Close()
	}

	if u.proxy != nil {
		u.proxy.Close()
	}
}
