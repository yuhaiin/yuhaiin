package nat

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
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

	sf singleflight.Group[string, *SourceTable]
}

func (u *Table) write(ctx context.Context, t *SourceTable, pkt *netapi.Packet) error {
	key := pkt.Dst.String()

	// ! we need write to same ip when use fakeip/domain, eg: quic will need it to create stream
	uaddr, ok := t.udpAddrCache.Load(key)
	if !ok {
		realAddr, err := u.dialer.Dispatch(ctx, pkt.Dst)
		if err != nil {
			return fmt.Errorf("dispatch addr failed: %w", err)
		}

		uaddr, err = realAddr.UDPAddr(ctx)
		if err != nil {
			return err
		}

		t.udpAddrCache.LoadOrStore(key, uaddr)

		if !pkt.Dst.IsFqdn() {
			addrPort, _ := pkt.Dst.AddrPort(ctx)
			uaddrPort := uaddr.AddrPort()
			// map fakeip/hosts
			if uaddrPort.Addr().Compare(addrPort.Addr()) != 0 || uaddrPort.Port() != addrPort.Port() {
				// TODO: maybe two dst(fake ip) have same uaddr, need help
				t.originAddrStore.LoadOrStore(addrPort, pkt.Dst)
			}
		}
	}

	_, err := t.dstPacketConn.WriteTo(pkt.Payload.Bytes(), uaddr)
	_ = t.dstPacketConn.SetReadDeadline(time.Now().Add(time.Minute))
	return err
}

func (u *Table) Write(ctx context.Context, pkt *netapi.Packet) error {
	defer pool.PutBytesBuffer(pkt.Payload)

	key := pkt.Src.String()

	t, ok := u.cache.Load(key)
	if ok {
		err := u.write(ctx, t, pkt)
		if err != nil {
			return fmt.Errorf("client to proxy failed: %w", err)
		}

		return nil
	}

	t, err, _ := u.sf.Do(key, func() (*SourceTable, error) {
		netapi.StoreFromContext(ctx).
			Add(netapi.SourceKey{}, pkt.Src).
			Add(netapi.DestinationKey{}, pkt.Dst)

		dstpconn, err := u.dialer.PacketConn(ctx, pkt.Dst)
		if err != nil {
			return nil, fmt.Errorf("dial %s failed: %w", pkt.Dst, err)
		}

		table, _ := u.cache.LoadOrStore(key,
			&SourceTable{dstPacketConn: dstpconn})

		go func() {
			defer func() {
				u.cache.Delete(key)
				dstpconn.Close()
			}()

			log.IfErr("udp remote to local",
				func() error { return u.writeBack(pkt, table) },
				net.ErrClosed,
				io.EOF,
				os.ErrDeadlineExceeded,
			)
		}()

		return table, nil
	})
	if err != nil {
		return err
	}

	if err = u.write(ctx, t, pkt); err != nil {
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
			return fmt.Errorf("read from proxy failed: %w", err)
		}

		faddr, err := netapi.ParseSysAddr(from)
		if err != nil {
			return fmt.Errorf("parse addr failed: %w", err)
		}

		if !faddr.IsFqdn() {
			addrPort, _ := faddr.AddrPort(context.TODO())
			if addr, ok := table.originAddrStore.Load(addrPort); ok {
				// TODO: maybe two dst(fake ip) have same uaddr, need help
				from = addr
			}
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
	originAddrStore syncmap.SyncMap[netip.AddrPort, netapi.Address]
	udpAddrCache    syncmap.SyncMap[string, *net.UDPAddr]
}
