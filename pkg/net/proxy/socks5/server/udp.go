package socks5server

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

// https://github.com/haxii/socks5/blob/bb9bca477f9b3ca36fa3b43e3127e3128da1c15b/udp.go#L20
// https://github.com/net-byte/socks5-server/blob/main/socks5/udp.go
type udpServer struct {
	listener net.PacketConn
	proxy    net.PacketConn

	remoteTarget net.Addr
	localRemote  net.Addr

	header     []byte
	headerSize int
}

func newUDPServer(f proxy.Proxy, target proxy.Address) (*udpServer, error) {
	l, err := net.ListenPacket("udp", "")
	if err != nil {
		return nil, fmt.Errorf("listen udp failed: %v", err)
	}

	p, err := f.PacketConn(target)
	if err != nil {
		return nil, fmt.Errorf("connect to %s failed: %v", target, err)
	}

	u := &udpServer{listener: l, proxy: p, remoteTarget: target}
	go u.forward()
	return u, nil
}

func (u *udpServer) forward() {
	buf := utils.GetBytes(utils.DefaultSize)
	defer utils.PutBytes(buf)
	for {
		n, l, err := u.listener.ReadFrom(buf)
		if err != nil {
			break
		}

		if u.header == nil {
			_, _, size, err := s5c.ResolveAddr(buf[3:n])
			if err != nil {
				log.Println("resolve addr failed:", err)
				continue
			}
			u.localRemote = l
			u.header = make([]byte, 3+size)
			copy(u.header, buf[:3+size])
			u.headerSize = len(u.header)
			go u.reply()
		}
		u.proxy.SetWriteDeadline(time.Now().Add(time.Second * 10))
		u.proxy.WriteTo(buf[u.headerSize:n], u.remoteTarget)
	}
}

func (u *udpServer) reply() {
	buf := utils.GetBytes(utils.DefaultSize)
	defer utils.PutBytes(buf)
	for {
		n, _, err := u.proxy.ReadFrom(buf)
		if err != nil {
			break
		}

		// log.Println(buf[:n])
		u.listener.SetWriteDeadline(time.Now().Add(time.Second * 10))
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
