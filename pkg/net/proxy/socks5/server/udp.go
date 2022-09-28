package socks5server

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

var MaxSegmentSize = (1 << 16) - 1

// https://github.com/haxii/socks5/blob/bb9bca477f9b3ca36fa3b43e3127e3128da1c15b/udp.go#L20
// https://github.com/net-byte/socks5-server/blob/main/socks5/udp.go
type udpServer struct {
	net.PacketConn
	remoteCache syncmap.SyncMap[string, net.PacketConn]
	remoteLock  syncmap.SyncMap[string, *sync.Cond]
}

func newUDPServer(f proxy.Proxy) (net.PacketConn, error) {
	l, err := dialer.ListenPacket("udp", "")
	if err != nil {
		return nil, fmt.Errorf("listen udp failed: %v", err)
	}

	u := &udpServer{PacketConn: l}
	go u.handle(f)
	return u, nil
}

func (u *udpServer) handle(dialer proxy.Proxy) {
	for {
		buf := utils.GetBytes(MaxSegmentSize)
		n, l, err := u.PacketConn.ReadFrom(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Errorln("read from local failed:", err)
			}
			return
		}

		go func(data []byte, n int, local net.Addr) {
			defer utils.PutBytes(data)
			if err := u.relay(data, n, local, dialer); err != nil {
				log.Errorln("relay failed:", err)
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
	data = data[3+size : n]

	ok := u.localToRemote(local, udpAddr, data)
	if ok {
		return nil
	}

	cond, ok := u.remoteLock.LoadOrStore(local.String(), sync.NewCond(&sync.Mutex{}))
	if ok {
		cond.L.Lock()
		cond.Wait()
		u.localToRemote(local, udpAddr, data)
		cond.L.Unlock()
		return nil
	}

	defer u.remoteLock.Delete(local.String())
	defer cond.Broadcast()

	remote, err := dialer.PacketConn(addr)
	if err != nil {
		return fmt.Errorf("dial %s failed: %w", addr, err)
	}
	u.remoteCache.Store(local.String(), remote)

	u.localToRemote(local, udpAddr, data)

	go func() {
		if err := u.remoteToLocal(remote, local, addr); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Errorln("remote to local failed:", err)
		}
		u.remoteCache.Delete(local.String())
		remote.Close()
	}()

	return nil
}

func (u *udpServer) localToRemote(local net.Addr, target *net.UDPAddr, data []byte) bool {
	r, ok := u.remoteCache.Load(local.String())
	if !ok {
		return false
	}

	if _, err := r.WriteTo(data, target); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Errorln("write to remote failed:", err)
	}

	// log.Println("udp write to", target, ":", len(data))

	return true
}

var udpTimeout = 60 * time.Second

func (u *udpServer) remoteToLocal(remote net.PacketConn, local net.Addr, host proxy.Address) error {
	data := utils.GetBytes(MaxSegmentSize)
	defer utils.PutBytes(data)

	for {
		remote.SetReadDeadline(time.Now().Add(udpTimeout))
		n, _, err := remote.ReadFrom(data)
		if err != nil {
			return fmt.Errorf("read from %s failed: %w", host, err)
		}

		// log.Println("udp read from", host, ad, ":", n)

		if _, err := u.PacketConn.WriteTo(bytes.Join([][]byte{{0, 0, 0}, s5c.ParseAddr(host), data[:n]}, nil), local); err != nil {
			return fmt.Errorf("response to local failed: %w", err)
		}
	}
}

func (u *udpServer) Close() error {
	u.remoteCache.Range(func(_ string, value net.PacketConn) bool {
		value.Close()
		return true
	})
	return u.PacketConn.Close()
}
