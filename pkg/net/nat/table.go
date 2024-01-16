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

var MaxSegmentSize = pool.MaxSegmentSize

func NewTable(dialer netapi.Proxy) *Table {
	return &Table{dialer: dialer}
}

type Table struct {
	dialer netapi.Proxy
	cache  syncmap.SyncMap[string, *SourceTable]

	sf singleflight.Group[string, struct{}]
}

func (u *Table) write(ctx context.Context, pkt *netapi.Packet, key string) (bool, error) {
	t, ok := u.cache.Load(key)
	if !ok {
		return false, nil
	}

	dst := pkt.Dst.String()

	uaddr, ok := t.udpAddrStore.Load(dst)
	if !ok {
		addr, err := u.dialer.Dispatch(ctx, pkt.Dst)
		if err != nil {
			return true, fmt.Errorf("dispatch addr failed: %w", err)
		}

		uaddr, err = addr.UDPAddr(ctx)
		if err != nil {
			return false, err
		}

		t.udpAddrStore.Store(dst, uaddr)

		if pkt.Dst.Type() == netapi.IP && uaddr.String() != pkt.Dst.String() {
			// TODO: maybe two dst(fake ip) have same uaddr, need help
			t.originAddrStore.LoadOrStore(uaddr.String(), pkt.Dst)
		}
	}

	_, err := t.dstPacketConn.WriteTo(pkt.Payload.Bytes(), uaddr)
	_ = t.dstPacketConn.SetReadDeadline(time.Now().Add(time.Minute))
	return true, err
}

func (u *Table) Write(ctx context.Context, pkt *netapi.Packet) error {
	defer pool.PutBytesBuffer(pkt.Payload)

	key := pkt.Src.String()

	ok, err := u.write(ctx, pkt, key)
	if err != nil {
		return fmt.Errorf("client to proxy failed: %w", err)
	}
	if ok {
		return nil
	}

	_, err, _ = u.sf.Do(key, func() (struct{}, error) {
		netapi.StoreFromContext(ctx).
			Add(netapi.SourceKey{}, pkt.Src).
			Add(netapi.DestinationKey{}, pkt.Dst)

		dstpconn, err := u.dialer.PacketConn(ctx, pkt.Dst)
		if err != nil {
			return struct{}{}, fmt.Errorf("dial %s failed: %w", pkt.Dst, err)
		}

		table, _ := u.cache.LoadOrStore(key, &SourceTable{dstPacketConn: dstpconn})

		go func() {
			defer func() {
				dstpconn.Close()
				u.cache.Delete(key)
			}()
			if err := u.writeBack(pkt, table); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Error("remote to local failed", "err", err)
			}
		}()

		return struct{}{}, nil
	})

	if err != nil {
		return err
	}

	if _, err = u.write(ctx, pkt, key); err != nil {
		return fmt.Errorf("write data to remote failed: %w", err)
	}

	return nil
}

func (u *Table) writeBack(pkt *netapi.Packet, table *SourceTable) error {
	data := pool.GetBytes(MaxSegmentSize)
	defer pool.PutBytes(data)

	for {
		_ = table.dstPacketConn.SetReadDeadline(time.Now().Add(time.Minute))
		n, from, err := table.dstPacketConn.ReadFrom(data)
		if err != nil {
			if ne, ok := err.(net.Error); (ok && ne.Timeout()) || errors.Is(err, io.EOF) || errors.Is(err, os.ErrDeadlineExceeded) {
				return nil /* ignore I/O timeout & EOF */
			}

			return fmt.Errorf("read from proxy failed: %w", err)
		}

		if addr, ok := table.originAddrStore.Load(from.String()); ok {
			// TODO: maybe two dst(fake ip) have same uaddr, need help
			from = addr
		}

		// write back to client with source address
		if _, err := pkt.WriteBack(data[:n], from); err != nil {
			return fmt.Errorf("write back to client failed: %w", err)
		}
	}
}

func (u *Table) Close() error {
	u.cache.Range(func(_ string, value *SourceTable) bool {
		value.dstPacketConn.Close()
		return true
	})

	return nil
}

type SourceTable struct {
	dstPacketConn   net.PacketConn
	originAddrStore syncmap.SyncMap[string, netapi.Address]
	udpAddrStore    syncmap.SyncMap[string, *net.UDPAddr]
}
