package nat

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/quic"
)

var udpDeadlineClockStart = time.Now()

type wrapConn struct {
	net.PacketConn
	mapper                  *addressMapper
	routeID                 string
	closed                  atomic.Bool
	nextReadDeadlineRefresh atomic.Int64
	closeOnce               sync.Once
	closeErr                error
}

func refreshPacketReadDeadline(conn net.PacketConn, timeout time.Duration) {
	if wrapped, ok := conn.(*wrapConn); ok {
		wrapped.refreshReadDeadline(timeout)
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
}

func (w *wrapConn) refreshReadDeadline(timeout time.Duration) {
	if timeout <= 0 {
		return
	}

	nowTick := time.Since(udpDeadlineClockStart).Nanoseconds()
	next := w.nextReadDeadlineRefresh.Load()
	if next > nowTick {
		return
	}

	refreshInterval := max(min(timeout/4, 30*time.Second), time.Second)
	if !w.nextReadDeadlineRefresh.CompareAndSwap(next, nowTick+refreshInterval.Nanoseconds()) {
		return
	}

	deadline := time.Now().Add(timeout + refreshInterval)
	if err := w.SetReadDeadline(deadline); err != nil {
		w.nextReadDeadlineRefresh.Store(0)
	}
}

func (w *wrapConn) Close() error {
	w.closed.Store(true)
	w.closeOnce.Do(func() { w.closeErr = w.PacketConn.Close() })
	return w.closeErr
}

func (u *SourceControl) handleOne(pkt *netapi.Packet) error {
	_, err := u.handleOneOwned(pkt, false)
	return err
}

func (u *SourceControl) handleOneOwned(pkt *netapi.Packet, queueReserved bool) (bool, error) {
	// Inbound migration is an admission event. Replaying packets after a stale
	// DNS result must not retarget replies back to their old inbound transport.
	if u.reply.Load().source == nil || pkt.MigrateID != 0 {
		u.bindReply(pkt)
	}
	return u.sendOneOwned(pkt, queueReserved)
}

func (u *SourceControl) sendOneOwned(pkt *netapi.Packet, queueReserved bool) (bool, error) {
	ctx := u.ctx

	// Only the source sender replaces the current connection.
	conn := u.conn

	if conn == nil || conn.closed.Load() {
		var err error

		store := netapi.GetContext(ctx)
		store.Source = u.reply.Load().source
		store.Destination = pkt.Dst()
		store.SetInboundName(pkt.InboundName())
		store.SetInboundID(pkt.InboundID())
		store.ConnOptions().SetIsUdp(true)

		if u.sniffer != nil {
			u.sniffer.Packet(store, pkt.GetPayload())
		}

		_, ok := pkt.Src().(*quic.QuicAddr)
		if !ok {
			src, err := netapi.ParseSysAddr(pkt.Src())
			if err == nil && !src.IsFqdn() {
				// Parsing an IP source does not require a DNS timeout.
				srcAddr := src.(netapi.IPAddress).AddrPort()
				if srcAddr.Addr().Unmap().Is4() {
					store.ConnOptions().Resolver().SetMode(netapi.ResolverModePreferIPv4)
				}
			}
		}

		ctx = store

		conn, err = u.newPacketConn(store, pkt)
		if err != nil {
			return false, err
		}

		u.conn = conn
		process := store.GetProcessName()
		u.lastProcess.Store(&process)
	}

	return u.writeOwned(ctx, pkt, conn, queueReserved)
}

func (u *SourceControl) newPacketConn(store *netapi.Context, pkt *netapi.Packet) (*wrapConn, error) {
	store.SetUDPMigrateID(u.contextCache.migrateID)
	if store.GetUDPMigrateID() != 0 {
		log.Info("set migrate id", "id", store.GetUDPMigrateID())
	}

	ctx, cancel := context.WithTimeout(store, configuration.Timeout)
	defer cancel()

	dstpconn, err := u.dialer.PacketConn(ctx, pkt.Dst())
	if err != nil {
		return nil, err
	}

	// A negotiated migration ID preserves the remote socket and its pinned
	// targets. A fresh socket starts a new mapping generation.
	previousID := u.contextCache.migrateID
	u.contextCache = newContextCache(store)
	if previousID == 0 || previousID != u.contextCache.migrateID {
		u.mapper = newAddressMapper()
	}

	routeID, _ := store.MatchedRule()
	conn := &wrapConn{PacketConn: dstpconn, mapper: u.mapper, routeID: routeID}
	// The caller releases pkt after handleOne returns; capture the address
	// before starting a worker that can outlive that packet reference.
	dst := pkt.Dst()
	u.readers.Add(1)
	u.workers.Go(func() { u.loopWriteBack(conn, dst) })

	return conn, nil
}
