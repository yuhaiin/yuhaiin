package nat

import (
	"context"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

const maxConcurrentResolutions = 4

type pendingResolution struct {
	key         uint64
	destination netapi.Address
	mapper      *addressMapper
	conn        net.PacketConn
	packets     []*netapi.Packet
}
type resolutionResult struct {
	pending *pendingResolution
	addr    *net.UDPAddr
	err     error
}

func (u *SourceControl) appendResolution(p *pendingResolution, pkt *netapi.Packet) error {
	if u.pendingPackets >= maxPendingPackets() {
		metrics.Counter.AddSendUDPDroppedPacket()
		return ErrSendPacketQueueFull
	}
	pkt.IncRef()
	u.pending.Add(1)
	u.pendingPackets++
	p.packets = append(p.packets, pkt)
	return nil
}

func (u *SourceControl) queueResolution(pkt *netapi.Packet, dst netapi.Address, conn net.PacketConn) error {
	p := &pendingResolution{key: pkt.Dst().Comparable(), destination: dst, mapper: u.mapper, conn: conn}
	if err := u.appendResolution(p, pkt); err != nil {
		return err
	}
	u.resolutions[p.key] = p
	u.resolveQueue = append(u.resolveQueue, p)
	u.startResolutions()
	return nil
}

func (u *SourceControl) startResolutions() {
	for u.resolving < maxConcurrentResolutions && len(u.resolveQueue) != 0 {
		p := u.resolveQueue[0]
		u.resolveQueue[0] = nil
		u.resolveQueue = u.resolveQueue[1:]
		u.resolving++
		// Resolver options are a snapshot; a replacement socket can select different
		// options while an old generation's lookup is still running.
		options := *u.contextCache.resolver
		u.workers.Go(func() {
			store := netapi.WithContext(u.ctx)
			store.ConnOptions().SetResolver(options)
			ctx, cancel := context.WithTimeout(store, 5*time.Second)
			defer cancel()
			ips, err := netapi.ResolverIP(ctx, p.destination.Hostname())
			var addr *net.UDPAddr
			if err == nil && (ips == nil || ips.Len() == 0) {
				err = &net.DNSError{Err: "no addresses", Name: p.destination.Hostname(), IsNotFound: true}
			}
			if err == nil {
				addr = ips.RandUDPAddr(p.destination.Port())
			}
			select {
			case u.resolved <- resolutionResult{p, addr, err}:
			case <-u.ctx.Done():
			}
		})
	}
}

func (u *SourceControl) finishResolution(result resolutionResult) {
	p := result.pending
	delete(u.resolutions, p.key)
	u.resolving--
	u.pendingPackets -= len(p.packets)
	// A replacement with a fresh socket may use new hosts/resolver settings.
	// Re-enter the sender instead of installing a result in the wrong generation.
	stale := p.mapper != u.mapper
	if conn, ok := p.conn.(*wrapConn); ok && conn.closed.Load() {
		stale = true
	}
	if !stale && result.err == nil {
		result.err = p.mapper.remember(p.packets[0].Dst(), result.addr)
	}
	for _, pkt := range p.packets {
		var err error
		if stale {
			err = u.sendOne(pkt)
		} else if result.err != nil {
			err = result.err
		} else {
			err = sendPacket(pkt.GetPayload(), result.addr, p.conn)
		}
		pkt.DecRef()
		u.pending.Add(-1)
		if err != nil {
			u.logPacketError(err)
		}
	}
	u.startResolutions()
}

func (u *SourceControl) drainResolutions() {
	for _, p := range u.resolutions {
		for _, pkt := range p.packets {
			pkt.DecRef()
			u.pending.Add(-1)
		}
	}
	clear(u.resolutions)
	u.resolveQueue = nil
	u.pendingPackets = 0
}
