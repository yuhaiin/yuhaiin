package nat

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/singleflight"
)

type waitPacket struct {
	ctx context.Context
	pkt *netapi.Packet
}

type Context struct {
	dstPacketConn net.PacketConn
	resolver      netapi.ContextResolver
	migrateID     uint64
	skipResolve   bool
}

func newContext(dstPacketConn net.PacketConn, store *netapi.Context) Context {
	return Context{
		dstPacketConn: dstPacketConn,
		resolver:      store.Resolver,
		migrateID:     store.UDPMigrateID,
		skipResolve:   store.Resolver.SkipResolve,
	}
}

func (c *Context) Close() error {
	conn := c.dstPacketConn
	if conn == nil {
		return nil
	}

	return conn.Close()
}

func (c *Context) WriteTo(b []byte, addr net.Addr) error {
	_, err := c.dstPacketConn.WriteTo(b, addr)
	_ = c.dstPacketConn.SetReadDeadline(time.Now().Add(IdleTimeout))
	return err
}

type SourceControl struct {
	Dialer netapi.Proxy

	stopTimer *time.Timer
	OnRemove  func()

	addrStore           addrStore
	resolveSingleFlight singleflight.GroupSync[string, *net.UDPAddr]

	context     Context
	waitPackets waitPackets

	mu sync.RWMutex

	connected  atomic.Bool
	connecting atomic.Bool
}

func (s *SourceControl) Close() error {
	err := s.context.Close()
	s.OnRemove()

	if s.stopTimer != nil {
		s.stopTimer.Stop()
	}

	return err
}

func (s *SourceControl) popWaitPackets() waitPackets {
	u := s.waitPackets
	s.waitPackets = nil
	return u
}

type waitPackets []*waitPacket

func (u waitPackets) rangeWaitPackets(ctx context.Context, pkt *netapi.Packet) iter.Seq2[context.Context, *netapi.Packet] {
	return func(f func(ctx context.Context, pkt *netapi.Packet) bool) {
		ctx, cancel := context.WithTimeout(ctx, configuration.Timeout)
		ok := f(ctx, pkt)
		cancel()
		pkt.DecRef()
		if !ok {
			return
		}

		for _, v := range u {
			ctx, cancel := context.WithTimeout(v.ctx, configuration.Timeout)
			ok := !f(ctx, v.pkt)
			cancel()
			v.pkt.DecRef()
			if !ok {
				return
			}
		}
	}
}

func (w waitPackets) DecRef() {
	for _, v := range w {
		v.pkt.DecRef()
	}
}

func (u *SourceControl) WritePacket(ctx context.Context, pkt *netapi.Packet) error {
	u.mu.RLock()
	if u.connected.Load() {
		err := u.write(ctx, pkt)
		u.mu.RUnlock()
		return err
	}
	u.mu.RUnlock()

	u.mu.Lock()
	defer u.mu.Unlock()

	if !u.connecting.CompareAndSwap(false, true) {
		pkt.IncRef()
		ctx = context.WithoutCancel(ctx)
		// TODO cache packets limit
		u.waitPackets = append(u.waitPackets, &waitPacket{ctx, pkt})
		return nil
	}

	ctx = context.WithoutCancel(ctx)
	pkt.IncRef()

	go func() {
		err := u.newPacketConn(ctx, pkt)

		u.mu.Lock()
		u.connecting.Store(false)
		waitPackets := u.popWaitPackets()
		u.mu.Unlock()

		fmt.Println("waitpackets", len(waitPackets))

		if err != nil {
			log.Select(netapi.LogLevel(err)).Print("new packet conn failed", "err", err)
			pkt.DecRef()
			waitPackets.DecRef()
			return
		}

		for ctx, pkt := range waitPackets.rangeWaitPackets(ctx, pkt) {
			u.mu.RLock()
			err = u.write(ctx, pkt)
			u.mu.RUnlock()
			if err != nil {
				log.Error("write packet failed", "err", err)
			}
		}
	}()

	return nil
}

func (u *SourceControl) newPacketConn(ctx context.Context, pkt *netapi.Packet) error {
	store := netapi.GetContext(ctx)
	store.Source = pkt.Src
	store.Destination = pkt.Dst
	store.UDPMigrateID = u.context.migrateID
	if store.UDPMigrateID != 0 {
		log.Info("set migrate id", "id", store.UDPMigrateID)
	}

	ctx, cancel := context.WithTimeout(ctx, configuration.Timeout)
	defer cancel()

	dstpconn, err := u.Dialer.PacketConn(ctx, pkt.Dst)
	if err != nil {
		return err
	}

	u.mu.Lock()

	if u.stopTimer != nil {
		u.stopTimer.Stop()
		u.stopTimer = nil
	}
	u.context = newContext(dstpconn, store)
	u.connected.Store(true)

	u.mu.Unlock()

	go u.loopWriteBack(pkt.WriteBack, dstpconn, pkt.Dst)

	return nil
}

func (t *SourceControl) write(ctx context.Context, pkt *netapi.Packet) error {
	key := pkt.Dst.String()

	// ! we need write to same ip when use fakeip/domain, eg: quic will need it to create stream
	udpAddr, ok := t.addrStore.LoadUdp(key)
	if ok {
		// load from cache, so we don't need to map addr, pkt is nil
		return t.WriteTo(pkt.Payload, udpAddr, nil)
	}

	store := netapi.GetContext(ctx)
	store.Resolver = t.context.resolver

	// cache fakeip/hosts/bypass address
	// for fullcone nat, we as much as possible write to same address
	dstAddr, ok := t.addrStore.LoadDispatch(key)
	if !ok {
		store.SkipRoute = true

		var err error
		dstAddr, err = t.Dialer.Dispatch(ctx, pkt.Dst)
		if err != nil {
			return fmt.Errorf("dispatch addr failed: %w", err)
		}

		if !pkt.Dst.Equal(dstAddr) {
			t.addrStore.StoreDispatch(key, dstAddr)
		}
	}

	// check is need resolve
	if !dstAddr.IsFqdn() || t.context.skipResolve {
		return t.WriteTo(pkt.Payload, dstAddr, pkt.Dst)
	}

	pkt.IncRef()
	// if addr need resolve(domain), make it run in background
	go func() {
		defer pkt.DecRef()

		ctx = context.WithoutCancel(ctx)

		ctx, cancel := context.WithTimeout(ctx, time.Second*5)
		defer cancel()

		udpAddr, err, _ := t.resolveSingleFlight.Do(ctx, key, func(ctx context.Context) (*net.UDPAddr, error) {
			udpAddr, err := dialer.ResolveUDPAddr(ctx, dstAddr)
			if err != nil {
				return nil, err
			}
			t.addrStore.StoreUdp(key, udpAddr)
			return udpAddr, nil
		})
		if err != nil {
			log.Error("resolve addr failed", "err", err)
			return
		}

		t.mu.RLock()
		err = t.WriteTo(pkt.Payload, udpAddr, pkt.Dst)
		t.mu.RUnlock()
		if err != nil {
			log.Error("write to addr failed", "err", err)
		}
	}()

	return nil
}

func (u *SourceControl) loopWriteBack(writeBack netapi.WriteBack, p net.PacketConn, dst netapi.Address) {
	defer func() {
		u.mu.Lock()
		u.stopTimer = time.AfterFunc(IdleTimeout, u.OnRemove)
		u.connected.Store(false)
		p.Close()
		u.mu.Unlock()
	}()

	ch := make(chan netapi.WriteBatchBuf, 250)
	defer close(ch)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		defer cancel()
		u.runChannel(writeBack, ch)
	}()

	data := pool.GetBytes(MaxSegmentSize)
	defer pool.PutBytes(data)

	for {
		_ = p.SetReadDeadline(time.Now().Add(IdleTimeout))
		n, from, err := p.ReadFrom(data)
		if err != nil {
			if ignoreError(err) {
				log.Debug("read from proxy break", "err", err, "dst", dst)
			} else {
				log.Error("read from proxy failed", "err", err, "dst", dst)
			}
			return
		}

		metrics.Counter.AddReceiveUDPPacket()

		payload := pool.Clone(data[:n])
		select {
		case ch <- netapi.WriteBatchBuf{Addr: u.parseAddr(from), Payload: payload}:
		case <-ctx.Done():
			pool.PutBytes(payload)
			return
		}
	}
}

func ignoreError(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, os.ErrDeadlineExceeded) ||
		errors.Is(err, io.EOF)
}

func (s *SourceControl) parseAddr(from net.Addr) net.Addr {
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

// func bumpWriteBuf(bc chan netapi.WriteBatchBuf, batchBufs []netapi.WriteBatchBuf) ([]netapi.WriteBatchBuf, bool) {
// 	pkt, ok := <-bc
// 	if !ok {
// 		return batchBufs, false
// 	}

// 	batchBufs = batchBufs[:0]

// 	batchBufs = append(batchBufs, pkt)

// 	for range min(len(bc), 11) {
// 		batchBufs = append(batchBufs, <-bc)
// 	}

// 	return batchBufs, true
// }

// runChannelBump
// ! it need more test for network quality and fair
// func (s *SourceControl) runChannelBump(writeBack netapi.WriteBack, bc chan netapi.WriteBatchBuf) {
// 	var batchBufs []netapi.WriteBatchBuf
// 	var ok bool
// 	for {
// 		batchBufs, ok = bumpWriteBuf(bc, batchBufs)
// 		if !ok {
// 			return
// 		}

// 		// write back to client with source address
// 		err := writeBack.WriteBatch(batchBufs...)
// 		for i := range batchBufs {
// 			pool.PutBytes(batchBufs[i].Payload)
// 		}
// 		if err != nil {
// 			if errors.Is(err, net.ErrClosed) {
// 				return
// 			}

// 			log.Error("write back failed", "err", err)
// 		}
// 	}
// }

func (s *SourceControl) runChannel(writeBack netapi.WriteBack, bc chan netapi.WriteBatchBuf) {
	for {
		pkt, ok := <-bc
		if !ok {
			return
		}

		_, err := writeBack.WriteBack(pkt.Payload, pkt.Addr)
		// write back to client with source address
		pool.PutBytes(pkt.Payload)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}

			log.Error("write back failed", "err", err)
		}
	}
}

func (t *SourceControl) mapAddr(src net.Addr, dst netapi.Address) {
	srcStr := src.String()
	dstStr := dst.String()

	if srcStr == dstStr {
		return
	}

	t.addrStore.StoreOrigin(srcStr, dst)
}

func (t *SourceControl) WriteTo(b []byte, realDst net.Addr, originDst netapi.Address) error {
	err := t.context.WriteTo(b, realDst)
	if err == nil && originDst != nil {
		t.mapAddr(realDst, originDst)
	}
	if err != nil && errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
