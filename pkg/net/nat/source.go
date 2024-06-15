package nat

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/singleflight"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type backPacket struct {
	from net.Addr
	buf  []byte
}

type cacheType int

const (
	cacheTypeOrigin cacheType = iota + 1
	cacheTypeDispatch
	cacheTypeUDPAddr
)

type cacheKey struct {
	Type cacheType
	Addr string
}

type udpAddr struct {
	addr *net.UDPAddr
	netapi.Address
}

type dispatchAddr struct {
	netapi.Address
	skipFqdn any
}

func (u *udpAddr) UDPAddr(context.Context) netapi.Result[*net.UDPAddr] {
	return netapi.NewResult(u.addr)
}

type SourceTable struct {
	dstPacketConn net.PacketConn

	addrStore syncmap.SyncMap[cacheKey, netapi.Address]
	sf        singleflight.Group[string, *net.UDPAddr]
	writeBack atomic.Pointer[netapi.WriteBack]
}

func (s *SourceTable) StoreUDPAddr(key string, addr *net.UDPAddr) {
	s.addrStore.Store(cacheKey{cacheTypeUDPAddr, key},
		&udpAddr{addr: addr, Address: netapi.EmptyAddr})
}

func (s *SourceTable) LoadUDPAddr(key string) (*net.UDPAddr, bool) {
	addr, ok := s.addrStore.Load(cacheKey{cacheTypeUDPAddr, key})
	if !ok {
		return nil, false
	}
	x, ok := addr.(*udpAddr)
	if !ok {
		return nil, false
	}

	return x.addr, true
}

func (s *SourceTable) StoreDispatchAddr(key string, addr netapi.Address, skipFqdn any) {
	s.addrStore.Store(cacheKey{cacheTypeDispatch, key},
		&dispatchAddr{Address: addr, skipFqdn: skipFqdn})
}

func (s *SourceTable) LoadDispatchAddr(key string) (netapi.Address, any, bool) {
	addr, ok := s.addrStore.Load(cacheKey{cacheTypeDispatch, key})
	if !ok {
		return netapi.EmptyAddr, false, false
	}

	x, ok := addr.(*dispatchAddr)
	if !ok {
		return netapi.EmptyAddr, false, false
	}

	return x.Address, x.skipFqdn, true
}

func (s *SourceTable) StoreOriginAddr(key string, addr netapi.Address) {
	s.addrStore.Store(cacheKey{cacheTypeOrigin, key}, addr)
}

func (s *SourceTable) LoadOriginAddr(key string) (netapi.Address, bool) {
	return s.addrStore.Load(cacheKey{cacheTypeOrigin, key})
}

func (s *SourceTable) runWriteBack(bc chan backPacket) error {
	for pkt := range bc {
		faddr, err := netapi.ParseSysAddr(pkt.from)
		if err != nil {
			log.Error("parse addr failed:", "err", err)
			pool.PutBytes(pkt.buf)
			continue
		}

		if addr, ok := s.LoadOriginAddr(faddr.String()); ok {
			// TODO: maybe two dst(fake ip) have same uaddr, need help
			pkt.from = addr
			// log.Info("map addr", "src", faddr, "dst", addr, "len", n)
		}

		// write back to client with source address
		_, err = (*s.writeBack.Load())(pkt.buf, pkt.from)
		if err != nil {
			pool.PutBytes(pkt.buf)
			return err
		}

		pool.PutBytes(pkt.buf)
	}

	return nil
}

func (t *SourceTable) mapAddr(src net.Addr, dst netapi.Address) {
	srcStr := src.String()
	dstStr := dst.String()

	if srcStr == dstStr {
		return
	}

	t.StoreOriginAddr(srcStr, dst)
}

func (t *SourceTable) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := t.dstPacketConn.WriteTo(b, addr)
	_ = t.dstPacketConn.SetReadDeadline(time.Now().Add(IdleTimeout))
	return n, err
}
