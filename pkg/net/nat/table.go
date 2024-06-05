package nat

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
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

type SkipResolveKey struct{}

func (u *Table) write(ctx context.Context, t *SourceTable, pkt *netapi.Packet, background bool) error {
	key := pkt.Dst.String()

	var err error
	// ! we need write to same ip when use fakeip/domain, eg: quic will need it to create stream
	uuaddr, ok := t.LoadUDPAddr(key)
	if ok {
		_, err = t.WriteTo(pkt.Payload, uuaddr)
		pool.PutBytes(pkt.Payload)
		return err
	}

	// cache fakeip/hosts/bypass address
	// because domain bypass maybe resolve domain which is speed some time, so we cache it for a while
	dispAddr, skipFqdn, ok := t.LoadDispatchAddr(key)
	if !ok {
		rAddr, err := u.dialer.Dispatch(ctx, pkt.Dst)
		if err != nil {
			return fmt.Errorf("dispatch addr failed: %w", err)
		}
		dispAddr = rAddr
		skipFqdn, _ = netapi.StoreFromContext(ctx).Get(SkipResolveKey{})

		t.StoreDispatchAddr(key, rAddr, skipFqdn)
	}

	// check is need resolve
	if !dispAddr.IsFqdn() || skipFqdn == true {
		_, err = t.WriteTo(pkt.Payload, dispAddr)
		if err == nil {
			t.mapAddr(dispAddr, pkt.Dst)
		}
		pool.PutBytes(pkt.Payload)
		return err
	}

	//
	// --------- proxy domain ------
	//

	write := func(ctx context.Context) error {
		defer pool.PutBytes(pkt.Payload)
		var err error
		uaddr, err, _ := t.sf.Do(key, func() (*net.UDPAddr, error) {
			ur := dispAddr.UDPAddr(ctx)
			if ur.Err != nil {
				return nil, ur.Err
			}

			udpAddr := ur.V

			t.StoreUDPAddr(key, udpAddr)

			t.mapAddr(udpAddr, pkt.Dst)
			return udpAddr, nil
		})
		if err != nil {
			return err
		}

		_, err = t.WriteTo(pkt.Payload, uaddr)
		return err
	}

	if background {
		return write(ctx)
	}

	// if need resolve, make it run in background
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
	pkt = pkt.Clone()

	key := pkt.Src.String()

	t, ok := u.cache.Load(key)
	if ok {
		// t.writeBack.Store(&pkt.WriteBack)
		return u.write(ctx, t, pkt, false)
	}

	go func() {
		ctx = context.WithoutCancel(ctx)

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

			go u.runWriteBack(key, dstpconn, table)

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

func (u *Table) runWriteBack(key string, p net.PacketConn, table *SourceTable) {
	defer u.cache.Delete(key)
	defer table.dstPacketConn.Close()
	defer p.Close()

	ch := make(chan backPacket, 250)
	defer close(ch)

	go func() {
		if err := table.runWriteBack(ch); err != nil {
			log.Error("run write back failed", "err", err)
			table.dstPacketConn.Close()
		}
	}()

	data := pool.GetBytes(MaxSegmentSize)
	defer pool.PutBytes(data)

	for {
		_ = table.dstPacketConn.SetReadDeadline(time.Now().Add(IdleTimeout))
		n, from, err := table.dstPacketConn.ReadFrom(data)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) ||
				errors.Is(err, context.Canceled) ||
				errors.Is(err, os.ErrDeadlineExceeded) ||
				errors.Is(err, io.EOF) {
				return
			}
			log.Error("read from proxy failed", "err", err)
			return
		}

		ch <- backPacket{from, pool.Clone(data[:n])}
	}
}

func (u *Table) Close() error {
	u.cache.Range(func(_ string, value *SourceTable) bool {
		value.dstPacketConn.Close()
		return true
	})

	return nil
}
