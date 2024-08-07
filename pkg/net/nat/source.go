package nat

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/singleflight"
)

type SourceTable struct {
	dstPacketConn net.PacketConn
	writeBack     netapi.WriteBack
	stopTimer     *time.Timer
	addrStore     addrStore
	sf            singleflight.GroupSync[string, *net.UDPAddr]
	resolver      netapi.ContextResolver
	batchBufs     []netapi.WriteBatchBuf
	migrateID     uint64
	connected     atomic.Bool
	skipResolve   bool
}

type Batchs struct {
	Addr net.Addr
	Buf  []byte
}
type BatchWriter interface {
	WriteBatch([]Batchs) error
}

func (s *SourceTable) parseAddr(from net.Addr) net.Addr {
	faddr, err := netapi.ParseSysAddr(from)
	if err != nil {
		log.Error("parse addr failed", "err", err)
		return from
	}

	if addr, ok := s.addrStore.LoadOrigin(faddr.String()); ok {
		// TODO: maybe two dst(fake ip) have same uaddr, need help
		from = addr
	}

	return from
}

func (s *SourceTable) bumpWriteBuf(bc chan netapi.WriteBatchBuf) bool {
	pkt, ok := <-bc
	if !ok {
		return false
	}

	s.batchBufs = s.batchBufs[:0]

	s.batchBufs = append(s.batchBufs, pkt)

	for range min(len(bc), 11) {
		s.batchBufs = append(s.batchBufs, <-bc)
	}

	return true
}

func (s *SourceTable) runWriteBack(bc chan netapi.WriteBatchBuf) {
	for {
		if !s.bumpWriteBuf(bc) {
			return
		}

		// write back to client with source address
		err := s.writeBack.WriteBatch(s.batchBufs...)
		for i := range s.batchBufs {
			pool.PutBytes(s.batchBufs[i].Payload)
		}
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}

			log.Error("write back failed", "err", err)
		}
	}
}

func (t *SourceTable) mapAddr(src net.Addr, dst netapi.Address) {
	srcStr := src.String()
	dstStr := dst.String()

	if srcStr == dstStr {
		return
	}

	t.addrStore.StoreOrigin(srcStr, dst)
}

func (t *SourceTable) WriteTo(b []byte, realDst net.Addr, pkt *netapi.Packet) error {
	_, err := t.dstPacketConn.WriteTo(b, realDst)
	_ = t.dstPacketConn.SetReadDeadline(time.Now().Add(IdleTimeout))
	if err == nil && pkt != nil {
		t.mapAddr(realDst, pkt.Dst)
	}
	if err != nil && errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (t *SourceTable) resolveWrite(ctx context.Context, dstAddr netapi.Address, pkt *netapi.Packet) error {
	key := pkt.Dst.String()
	udpAddr, err, _ := t.sf.Do(key, func() (*net.UDPAddr, error) {
		udpAddr, err := netapi.ResolveUDPAddr(ctx, dstAddr)
		if err != nil {
			return nil, err
		}
		t.addrStore.StoreUdp(key, udpAddr)
		return udpAddr, nil
	})
	if err != nil {
		return err
	}

	return t.WriteTo(pkt.Payload, udpAddr, pkt)
}
