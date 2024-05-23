package nat

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/singleflight"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

var IdleTimeout = time.Minute * 3 / 2
var MaxSegmentSize = pool.MaxSegmentSize

func NewTable(dialer netapi.Proxy) *Table {
	return &Table{dialer: dialer}
}

type Table struct {
	dialer netapi.Proxy
	cache  syncmap.SyncMap[string, *SourceTable]
	sf     singleflight.Group[string, *SourceTable]
}

func (u *Table) write(ctx context.Context, t *SourceTable, pkt *netapi.Packet, background bool) error {
	key := pkt.Dst.String()

	// ! we need write to same ip when use fakeip/domain, eg: quic will need it to create stream
	uaddr, ok := t.udpAddrCache.Load(key)
	if ok {
		defer pkt.Payload.Free()
		_, err := t.dstPacketConn.WriteTo(pkt.Payload.Bytes(), uaddr)
		_ = t.dstPacketConn.SetReadDeadline(time.Now().Add(IdleTimeout))
		return err
	}

	write := func(ctx context.Context) error {
		defer pkt.Payload.Free()
		var err error
		uaddr, err, _ = t.sf.Do(key, func() (*net.UDPAddr, error) {
			realAddr, err := u.dialer.Dispatch(ctx, pkt.Dst)
			if err != nil {
				return nil, fmt.Errorf("dispatch addr failed: %w", err)
			}

			ur := realAddr.UDPAddr(ctx)
			if ur.Err != nil {
				return nil, ur.Err
			}

			uaddr = ur.V

			t.udpAddrCache.LoadOrStore(key, uaddr)

			if !pkt.Dst.IsFqdn() {
				// map fakeip/hosts
				if uaddrStr := uaddr.String(); pkt.Dst.AddrPort(ctx).V.Compare(uaddr.AddrPort()) != 0 {
					// TODO: maybe two dst(fake ip) have same uaddr, need help
					t.originAddrStore.LoadOrStore(uaddrStr, pkt.Dst)
				}
			}

			return uaddr, nil
		})
		if err != nil {
			return err
		}

		_, err = t.dstPacketConn.WriteTo(pkt.Payload.Bytes(), uaddr)
		_ = t.dstPacketConn.SetReadDeadline(time.Now().Add(IdleTimeout))
		return err
	}

	if background || pkt.Dst.Type() == netapi.IP {
		return write(ctx)
	}

	go func() {
		ctx = context.WithoutCancel(ctx)
		ctx, cancel := context.WithTimeout(ctx, time.Second*5)
		defer cancel()

		if err := write(ctx); err != nil {
			log.Error("udp write to remote failed", "err", err)
		}
	}()
	return nil
}

func (u *Table) Write(ctx context.Context, pkt *netapi.Packet) error {
	key := pkt.Src.String()

	t, ok := u.cache.Load(key)
	if ok {
		// t.writeBack.Store(&pkt.WriteBack)
		return u.write(ctx, t, pkt, false)
	}

	go func() {
		ctx = context.WithoutCancel(ctx)

		defer pkt.Payload.Free()
		t, err, _ := u.sf.Do(key, func() (*SourceTable, error) {
			netapi.StoreFromContext(ctx).
				Add(netapi.SourceKey{}, pkt.Src).
				Add(netapi.DestinationKey{}, pkt.Dst)

			dstpconn, err := u.dialer.PacketConn(ctx, pkt.Dst)
			if err != nil {
				return nil, fmt.Errorf("dial %s failed: %w", pkt.Dst, err)
			}

			table, _ := u.cache.LoadOrStore(key, &SourceTable{dstPacketConn: dstpconn})

			table.writeBack.Store(&pkt.WriteBack)

			go func() {
				if err := u.writeBack(table); err != nil {
					log.Error("udp remote to local", "err", err)
				}
				u.cache.Delete(key)
				dstpconn.Close()
			}()

			return table, nil
		})
		if err != nil {
			log.Error("udp remote to local", "err", err)
			return
		}

		if err = u.write(ctx, t, pkt, true); err != nil {
			log.Error("udp remote to local", "err", err)
		}
	}()

	return nil
}

func (u *Table) writeBack(table *SourceTable) error {

	ch := make(chan backPacket, 250)
	defer close(ch)

	go table.runWriteBack(ch)

	data := pool.GetBytesBuffer(MaxSegmentSize)
	defer data.Free()

	for {
		data.Reset()
		_ = table.dstPacketConn.SetReadDeadline(time.Now().Add(IdleTimeout))
		n, from, err := table.dstPacketConn.ReadFrom(data.Bytes())
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) ||
				errors.Is(err, context.Canceled) ||
				errors.Is(err, os.ErrDeadlineExceeded) ||
				errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read from proxy failed: %w", err)
		}

		data.Refactor(0, n)

		ch <- backPacket{from, pool.GetBytesBuffer(data.Len()).Copy(data.Bytes())}
	}
}

func (u *Table) Close() error {
	u.cache.Range(func(_ string, value *SourceTable) bool {
		value.dstPacketConn.Close()
		return true
	})

	return nil
}

type backPacket struct {
	from net.Addr
	buf  *pool.Bytes
}

type SourceTable struct {
	dstPacketConn   net.PacketConn
	originAddrStore syncmap.SyncMap[string, netapi.Address]
	udpAddrCache    syncmap.SyncMap[string, *net.UDPAddr]
	sf              singleflight.Group[string, *net.UDPAddr]
	writeBack       atomic.Pointer[netapi.WriteBack]
}

func (s *SourceTable) runWriteBack(bc chan backPacket) {
	for pkt := range bc {
		faddr, err := netapi.ParseSysAddr(pkt.from)
		if err != nil {
			log.Error("parse addr failed:", "err", err)
			pkt.buf.Free()
			continue
		}

		if !faddr.IsFqdn() {
			if addr, ok := s.originAddrStore.Load(faddr.String()); ok {
				// TODO: maybe two dst(fake ip) have same uaddr, need help
				pkt.from = addr

				// log.Info("map addr", "src", faddr, "dst", addr, "len", n)
			}
		}

		// write back to client with source address
		_, err = (*s.writeBack.Load())(pkt.buf.Bytes(), pkt.from)
		if err != nil {
			log.Error("write back to client failed:", "err", err)
		}

		pkt.buf.Free()
	}
}
