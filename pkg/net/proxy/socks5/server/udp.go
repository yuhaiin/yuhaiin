package socks5server

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
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
	netTable *NatTable
}

func newUDPServer(f proxy.Proxy) (net.PacketConn, error) {
	l, err := dialer.ListenPacket("udp", "")
	if err != nil {
		return nil, fmt.Errorf("listen udp failed: %v", err)
	}

	u := &udpServer{PacketConn: l, netTable: NewNatTable(f)}
	go u.handle(f)
	return u, nil
}

func (u *udpServer) handle(dialer proxy.Proxy) {
	for {
		buf := pool.GetBytes(MaxSegmentSize)
		n, raddr, err := u.PacketConn.ReadFrom(buf)
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
		}(buf, n, raddr)
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

type NatTable struct {
	dialer proxy.Proxy
	cache  syncmap.SyncMap[string, net.PacketConn]
	lock   syncmap.SyncMap[string, *sync.Cond]
}

func NewNatTable(dialer proxy.Proxy) *NatTable {
	return &NatTable{dialer: dialer}
}

func (u *NatTable) writeTo(data []byte, src, dst net.Addr) (bool, error) {
	dstpconn, ok := u.cache.Load(src.String())
	if !ok {
		return false, nil
	}

	if _, err := dstpconn.WriteTo(data, dst); err != nil && !errors.Is(err, net.ErrClosed) {
		return true, err
	}

	return true, nil
}

func (u *NatTable) Write(data []byte, src net.Addr, dst proxy.Address, srcpconn net.PacketConn) error {
	ok, err := u.writeTo(data, src, dst)
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
		u.writeTo(data, src, dst)
		cond.L.Unlock()
		return nil
	}

	defer u.lock.Delete(src.String())
	defer cond.Broadcast()

	dst.WithValue(proxy.SourceKey{}, src)
	dst.WithValue(proxy.DestinationKey{}, dst)

	dstpconn, err := u.dialer.PacketConn(dst)
	if err != nil {
		return fmt.Errorf("dial %s failed: %w", dst, err)
	}
	u.cache.Store(src.String(), dstpconn)

	u.writeTo(data, src, dst)

	go func() {
		defer dstpconn.Close()
		defer u.cache.Delete(src.String())
		if err := u.relay(dstpconn, srcpconn, src); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Errorln("remote to local failed:", err)
		}
	}()

	return nil
}

func (u *NatTable) relay(dstpconn, srcpconn net.PacketConn, src net.Addr) error {
	data := pool.GetBytes(MaxSegmentSize)
	defer pool.PutBytes(data)

	for {
		dstpconn.SetReadDeadline(time.Now().Add(time.Minute))
		n, _, err := dstpconn.ReadFrom(data)
		if err != nil {
			if ne, ok := err.(net.Error); (ok && ne.Timeout()) || errors.Is(err, io.EOF) || errors.Is(err, os.ErrDeadlineExceeded) {
				return nil /* ignore I/O timeout & EOF */
			}

			return fmt.Errorf("read from proxy failed: %w", err)
		}

		if _, err := srcpconn.WriteTo(data[:n], src); err != nil {
			return fmt.Errorf("write back to client failed: %w", err)
		}
	}
}

func (u *NatTable) Close() error {
	u.cache.Range(func(_ string, value net.PacketConn) bool {
		value.Close()
		return true
	})

	return nil
}
