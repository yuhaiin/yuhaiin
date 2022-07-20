package socks5server

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

var MaxSegmentSize = (1 << 16) - 1

// https://github.com/haxii/socks5/blob/bb9bca477f9b3ca36fa3b43e3127e3128da1c15b/udp.go#L20
// https://github.com/net-byte/socks5-server/blob/main/socks5/udp.go
type udpServer struct{ net.PacketConn }

func newUDPServer(f proxy.Proxy) (net.PacketConn, error) {
	l, err := dialer.ListenPacket("udp", "")
	if err != nil {
		return nil, fmt.Errorf("listen udp failed: %v", err)
	}

	u := &udpServer{l}
	go u.handle(f)
	return u, nil
}

func (u *udpServer) handle(dialer proxy.Proxy) {
	for {
		buf := utils.GetBytes(MaxSegmentSize)
		n, l, err := u.PacketConn.ReadFrom(buf)
		if err != nil {
			break
		}

		go func(data []byte, n int, local net.Addr) {
			defer utils.PutBytes(data)
			if err := u.relay(data, n, local, dialer); err != nil {
				log.Println("relay failed:", err)
			}
		}(buf, n, l)
	}
}

func (u *udpServer) relay(data []byte, n int, local net.Addr, dialer proxy.Proxy) error {
	addr, size, err := s5c.ResolveAddr("udp", bytes.NewBuffer(data[3:n]))
	if err != nil {
		return fmt.Errorf("resolve addr failed: %w", err)
	}
	udpAddr, err := addr.UDPAddr()
	if err != nil {
		return fmt.Errorf("resolve udp addr failed: %w", err)
	}

	remote, err := dialer.PacketConn(addr)
	if err != nil {
		return fmt.Errorf("dial %s failed: %w", addr, err)
	}
	defer remote.Close()

	remote.SetWriteDeadline(time.Now().Add(time.Second * 10))
	if _, err = remote.WriteTo(data[3+size:n], udpAddr); err != nil {
		return fmt.Errorf("write to %s failed: %w", addr, err)
	}

	header := utils.GetBytes(3 + size)
	defer utils.PutBytes(header)
	copy(header[:3+size], data[:3+size])

	remote.SetReadDeadline(time.Now().Add(time.Second * 15))
	n, _, err = remote.ReadFrom(data)
	if err != nil {
		return fmt.Errorf("read from %s failed: %w", addr, err)
	}
	if _, err := u.PacketConn.WriteTo(append(header[:3+size], data[:n]...), local); err != nil {
		return fmt.Errorf("response to local failed: %w", err)
	}

	return nil
}
