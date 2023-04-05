package nat

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

var MaxSegmentSize = (1 << 16) - 1

func NewTable(dialer proxy.Proxy) *Table {
	return &Table{dialer: dialer}
}

type Table struct {
	dialer proxy.Proxy
	cache  syncmap.SyncMap[string, *SourceTable]
	mu     syncmap.SyncMap[string, *sync.Cond]
}

func (u *Table) write(ctx context.Context, pkt *Packet, key string) (bool, error) {
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

		if uaddr.String() != pkt.Dst.String() {
			// TODO: maybe two dst(fake ip) have same uaddr, need help
			t.originAddrStore.LoadOrStore(uaddr.String(), pkt.Dst)
		}
	}

	_, err := t.dstPacketConn.WriteTo(pkt.Payload, uaddr)
	t.dstPacketConn.SetReadDeadline(time.Now().Add(time.Minute))
	return true, err
}

type Packet struct {
	Src       net.Addr
	Dst       proxy.Address
	WriteBack func(b []byte, addr net.Addr) (int, error)
	Payload   []byte
}

func (u *Table) Write(ctx context.Context, pkt *Packet) error {
	key := pkt.Src.String()

	ok, err := u.write(ctx, pkt, key)
	if err != nil {
		return fmt.Errorf("client to proxy failed: %w", err)
	}
	if ok {
		log.Verboseln("nat table use **old** udp addr write to:", pkt.Dst, "from", pkt.Src)
		return nil
	}

	log.Verboseln("nat table write to:", pkt.Dst, "from", pkt.Src)

	cond, ok := u.mu.LoadOrStore(key, sync.NewCond(&sync.Mutex{}))
	if ok {
		cond.L.Lock()
		cond.Wait()
		_, err := u.write(ctx, pkt, key)
		cond.L.Unlock()
		return err
	}

	defer u.mu.Delete(key)
	defer cond.Broadcast()

	pkt.Dst.WithValue(proxy.SourceKey{}, pkt.Src)
	pkt.Dst.WithValue(proxy.DestinationKey{}, pkt.Dst)

	dstpconn, err := u.dialer.PacketConn(ctx, pkt.Dst)
	if err != nil {
		return fmt.Errorf("dial %s failed: %w", pkt.Dst, err)
	}

	table, _ := u.cache.LoadOrStore(key, &SourceTable{dstPacketConn: dstpconn})

	if _, err = u.write(ctx, pkt, key); err != nil {
		return fmt.Errorf("write data to remote failed: %w", err)
	}

	pkt.Payload = nil

	go func() {
		defer func() {
			dstpconn.Close()
			u.cache.Delete(key)
		}()
		if err := u.writeBack(pkt, table); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Errorln("remote to local failed:", err)
		}
	}()

	return nil
}

func (u *Table) writeBack(pkt *Packet, table *SourceTable) error {
	data := pool.GetBytes(MaxSegmentSize)
	defer pool.PutBytes(data)

	for {
		table.dstPacketConn.SetReadDeadline(time.Now().Add(time.Minute))
		n, from, err := table.dstPacketConn.ReadFrom(data)
		if err != nil {
			if ne, ok := err.(net.Error); (ok && ne.Timeout()) || errors.Is(err, io.EOF) || errors.Is(err, os.ErrDeadlineExceeded) {
				return nil /* ignore I/O timeout & EOF */
			}

			return fmt.Errorf("read from proxy failed: %w", err)
		}

		log.Verboseln("nat table read data length:", n, "from", from, "dst:", pkt.Dst, "fakeIP:", pkt.Dst, "maybe write to:", pkt.Src)

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
	originAddrStore syncmap.SyncMap[string, proxy.Address]
	udpAddrStore    syncmap.SyncMap[string, *net.UDPAddr]
}
