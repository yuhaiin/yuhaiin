package nat

import (
	"log/slog"
	"net"
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
	Addr string
	Type cacheType
}

type SourceTable struct {
	dstPacketConn net.PacketConn
	sf            singleflight.GroupSync[string, *net.UDPAddr]
	writeBack     netapi.WriteBack
	addrStore     syncmap.SyncMap[cacheKey, net.Addr]
	skipResolve   bool
}

func loadSourceTableAddr[T net.Addr](s *SourceTable, t cacheType, key string) (T, bool) {
	addr, ok := s.addrStore.Load(cacheKey{key, t})
	if !ok {
		return *new(T), false
	}
	x, ok := addr.(T)
	if !ok {
		return *new(T), false
	}
	return x, true
}

func (s *SourceTable) storeAddr(t cacheType, key string, addr net.Addr) {
	s.addrStore.Store(cacheKey{key, t}, addr)
}

func (s *SourceTable) runWriteBack(bc chan backPacket) {
	for pkt := range bc {
		faddr, err := netapi.ParseSysAddr(pkt.from)
		if err != nil {
			log.Error("parse addr failed:", "err", err)
			pool.PutBytes(pkt.buf)
			continue
		}

		if addr, ok := loadSourceTableAddr[netapi.Address](s, cacheTypeOrigin, faddr.String()); ok {
			// TODO: maybe two dst(fake ip) have same uaddr, need help
			pkt.from = addr
			// log.Info("map addr", "src", faddr, "dst", addr, "len", n)
		}

		// write back to client with source address
		_, err = s.writeBack(pkt.buf, pkt.from)
		if err != nil {
			pool.PutBytes(pkt.buf)
			slog.Error("write back failed", "err", err)
			continue
		}

		pool.PutBytes(pkt.buf)
	}
}

func (t *SourceTable) mapAddr(src net.Addr, dst netapi.Address) {
	srcStr := src.String()
	dstStr := dst.String()

	if srcStr == dstStr {
		return
	}

	t.storeAddr(cacheTypeOrigin, srcStr, dst)
}

func (t *SourceTable) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := t.dstPacketConn.WriteTo(b, addr)
	_ = t.dstPacketConn.SetReadDeadline(time.Now().Add(IdleTimeout))
	return n, err
}
