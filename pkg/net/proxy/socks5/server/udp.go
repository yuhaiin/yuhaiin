package socks5server

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

var MaxSegmentSize = (1 << 16) - 1

// https://github.com/haxii/socks5/blob/bb9bca477f9b3ca36fa3b43e3127e3128da1c15b/udp.go#L20
// https://github.com/net-byte/socks5-server/blob/main/socks5/udp.go
type udpServer struct {
	net.PacketConn
	netTable *UdpNatTable
}

func newUDPServer(f proxy.Proxy) (net.PacketConn, error) {
	l, err := dialer.ListenPacket("udp", "")
	if err != nil {
		return nil, fmt.Errorf("listen udp failed: %v", err)
	}

	u := &udpServer{PacketConn: l, netTable: NewUdpNatTable(f)}
	go u.handle(f)
	return u, nil
}

func (u *udpServer) handle(dialer proxy.Proxy) {
	for {
		buf := pool.GetBytes(MaxSegmentSize)
		n, l, err := u.PacketConn.ReadFrom(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Errorln("read from local failed:", err)
			}
			return
		}

		go func(data []byte, n int, src net.Addr) {
			defer pool.PutBytes(data)
			addr, size, err := s5c.ResolveAddr("udp", bytes.NewBuffer(data[3:n]))
			if err != nil {
				log.Errorf("resolve addr failed: %v", err)
				return
			}

			err = u.netTable.Write(data[3+size:n], src, addr,
				&localPacketConn{u.PacketConn, s5c.ParseAddr(addr)})
			if err != nil {
				log.Errorln("write to nat table failed:", err)
			}
		}(buf, n, l)
	}
}

func (u *udpServer) Close() error {
	u.netTable.Close()
	return u.PacketConn.Close()
}

type localPacketConn struct {
	net.PacketConn
	addr []byte
}

func (l *localPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return l.PacketConn.WriteTo(bytes.Join([][]byte{{0, 0, 0}, l.addr, b}, nil), addr)
}

type UdpNatTable struct {
	dialer proxy.Proxy
	cache  syncmap.SyncMap[string, net.PacketConn]
	lock   syncmap.SyncMap[string, *sync.Cond]
}

func NewUdpNatTable(dialer proxy.Proxy) *UdpNatTable {
	return &UdpNatTable{dialer: dialer}
}

func (u *UdpNatTable) writeTo(data []byte, src, target net.Addr) (bool, error) {
	r, ok := u.cache.Load(src.String())
	if !ok {
		return false, nil
	}

	if _, err := r.WriteTo(data, target); err != nil && !errors.Is(err, net.ErrClosed) {
		return true, err
	}

	return true, nil
}

type clientAddress struct{}

func (clientAddress) String() string { return "Client" }

func (u *UdpNatTable) Write(data []byte, src net.Addr, target proxy.Address, client net.PacketConn) error {
	ok, err := u.writeTo(data, src, target)
	if err != nil {
		return fmt.Errorf("client to proxy failed: %w", err)
	}
	if ok {
		return nil
	}

	cond, ok := u.lock.LoadOrStore(src.String(), sync.NewCond(&sync.Mutex{}))
	if ok {
		cond.L.Lock()
		cond.Wait()
		u.writeTo(data, src, target)
		cond.L.Unlock()
		return nil
	}

	defer u.lock.Delete(src.String())
	defer cond.Broadcast()

	target.WithValue(clientAddress{}, src)

	proxy, err := u.dialer.PacketConn(target)
	if err != nil {
		return fmt.Errorf("dial %s failed: %w", target, err)
	}
	u.cache.Store(src.String(), proxy)

	u.writeTo(data, src, target)

	go func() {
		if err := u.relay(proxy, client, src); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Errorln("remote to local failed:", err)
		}
	}()

	return nil
}

func (u *UdpNatTable) relay(proxy, client net.PacketConn, src net.Addr) error {
	data := pool.GetBytes(MaxSegmentSize)
	defer pool.PutBytes(data)

	defer u.cache.Delete(src.String())
	defer proxy.Close()

	for {
		proxy.SetReadDeadline(time.Now().Add(time.Minute))
		n, _, err := proxy.ReadFrom(data)
		if err != nil {
			if ne, ok := err.(net.Error); (ok && ne.Timeout()) || err == io.EOF {
				return nil /* ignore I/O timeout & EOF */
			}

			return fmt.Errorf("read from proxy failed: %w", err)
		}

		if _, err := client.WriteTo(data[:n], src); err != nil {
			return fmt.Errorf("write back to client failed: %w", err)
		}
	}
}

func (u *UdpNatTable) Close() error {
	u.cache.Range(func(_ string, value net.PacketConn) bool {
		value.Close()
		return true
	})

	return nil
}
