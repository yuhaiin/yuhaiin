package socks5server

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
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

	for i := 0; i < runtime.GOMAXPROCS(0); i++ {
		go u.handle()
	}

	return u, nil
}

func (u *udpServer) handle() {
	buf := pool.GetBytes(MaxSegmentSize)
	defer pool.PutBytes(buf)

	for {
		n, raddr, err := u.PacketConn.ReadFrom(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Errorln("read from local failed:", err)
			}
			return
		}

		addr, err := s5c.ResolveAddr(bytes.NewReader(buf[3:n]))
		if err != nil {
			log.Errorf("resolve addr failed: %v", err)
			return
		}

		err = u.netTable.Write(
			buf[3+len(addr):n], raddr,
			addr.Address(statistic.Type_udp),
			func(b []byte, adr net.Addr) (int, error) {
				return u.PacketConn.WriteTo(bytes.Join([][]byte{{0, 0, 0}, addr, b}, nil), adr)
			})
		if err != nil && !errors.Is(err, os.ErrClosed) {
			log.Errorln("write to nat table failed:", err)
		}
	}
}

func (u *udpServer) Close() error {
	u.netTable.Close()
	return u.PacketConn.Close()
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
	_, err := dstpconn.WriteTo(data, dst)
	return true, err
}

func (u *NatTable) Write(data []byte, src net.Addr, dst proxy.Address, writeBack func(b []byte, addr net.Addr) (int, error)) error {
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
		_, err := u.writeTo(data, src, dst)
		cond.L.Unlock()
		return err
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

	if _, err = u.writeTo(data, src, dst); err != nil {
		return fmt.Errorf("write data to remote failed: %w", err)
	}

	go func() {
		defer dstpconn.Close()
		defer u.cache.Delete(src.String())
		if err := u.relay(dstpconn, writeBack, src); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Errorln("remote to local failed:", err)
		}
	}()

	return nil
}

func (u *NatTable) relay(dstpconn net.PacketConn, writeBack func(b []byte, addr net.Addr) (int, error), src net.Addr) error {
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

		if _, err := writeBack(data[:n], src); err != nil {
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
