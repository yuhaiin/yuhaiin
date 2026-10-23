package nat

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

// Bound retained addresses without evicting reverse mappings for active flows.
// Ordinary IP destinations remain usable when the forward cache is full.
const maxCachedDestinations = 1024

var errReverseMappingFull = errors.New("UDP reverse mapping limit reached")

type addressMapper struct {
	// The sender owns targets and reverseCount. Readers only access reverse.
	targets      map[uint64]net.Addr
	reverse      syncmap.SyncMap[uint64, netapi.Address]
	reverseCount int
	hasReverse   atomic.Bool
}

func newAddressMapper() *addressMapper { return &addressMapper{targets: make(map[uint64]net.Addr)} }

func (m *addressMapper) remember(original netapi.Address, real net.Addr) error {
	addr, err := netapi.ParseSysAddr(real)
	if err != nil {
		return err
	}
	key := addr.Comparable()
	if key != original.Comparable() {
		if _, exists := m.reverse.Load(key); !exists {
			if m.reverseCount >= maxCachedDestinations {
				return errReverseMappingFull
			}
			m.reverseCount++
		}
		// Preserve the existing last-alias-wins policy: full cone replies contain
		// no information to distinguish two aliases of the same remote endpoint.
		m.reverse.Store(key, original)
		m.hasReverse.Store(true)
	}
	if len(m.targets) < maxCachedDestinations {
		m.targets[original.Comparable()] = real
	}
	return nil
}

func (m *addressMapper) replyAddr(from net.Addr) net.Addr {
	if !m.hasReverse.Load() {
		return from
	}
	addr, err := netapi.ParseSysAddr(from)
	if err != nil {
		return from
	}
	if original, ok := m.reverse.Load(addr.Comparable()); ok {
		return original
	}
	return from
}

func (u *SourceControl) write(ctx context.Context, pkt *netapi.Packet, conn net.PacketConn) error {
	_, err := u.writeOwned(ctx, pkt, conn, false)
	return err
}

func (u *SourceControl) writeOwned(ctx context.Context, pkt *netapi.Packet, conn net.PacketConn, queueReserved bool) (bool, error) {
	if u.mapper == nil {
		u.mapper = newAddressMapper()
	}
	key := pkt.Dst().Comparable()
	if real, ok := u.mapper.targets[key]; ok {
		return false, u.writeRoutedPacket(pkt, pkt.GetPayload(), real, conn)
	}
	if pending := u.resolutions[key]; pending != nil {
		if err := u.appendResolutionOwned(pending, pkt, queueReserved); err != nil {
			return false, err
		}
		return true, nil
	}

	store := netapi.GetContext(ctx)
	// A later destination on an existing source still needs trusted ingress
	// metadata. Destination authorization is independent of SkipRoute.
	store.Source = pkt.Src()
	store.SetInboundID(pkt.InboundID())
	store.SetInboundName(pkt.InboundName())
	store.ConnOptions().SetSkipRoute(true)
	dst, err := u.dialer.Dispatch(store, pkt.Dst())
	if err != nil {
		return false, fmt.Errorf("dispatch addr failed: %w", err)
	}
	if dst.IsFqdn() && !u.contextCache.resolver.UdpSkipResolveTarget() {
		return u.queueResolution(pkt, dst, conn, queueReserved)
	}
	// Publish before the send: a fast remote can reply before WriteTo returns,
	// and retrying a failed first send must retain a complete mapping.
	if err := u.mapper.remember(pkt.Dst(), dst); err != nil {
		return false, err
	}
	u.retainDestinationLease(key)
	return false, u.writeRoutedPacket(pkt, pkt.GetPayload(), dst, conn)
}

func (u *SourceControl) writeRoutedPacket(pkt *netapi.Packet, data []byte, dst net.Addr, conn net.PacketConn) error {
	var original netapi.Address
	if pkt != nil {
		original = pkt.Dst()
	}
	return u.writeAuthorizedPacket(pkt, data, dst, original, conn)
}

func (u *SourceControl) writeAuthorizedPacket(pkt *netapi.Packet, data []byte, dst net.Addr, original netapi.Address, conn net.PacketConn) error {
	if u.access != nil {
		if err := u.access.Authorize(original, dst); err != nil {
			return err
		}
	}
	if u.trafficControl != nil {
		inboundID := ""
		if pkt != nil {
			inboundID = pkt.InboundID()
			if inboundID == "" {
				inboundID = pkt.InboundName()
			}
		} else if reply := u.reply.Load(); reply != nil {
			inboundID = reply.inboundID
		}
		routeID := ""
		if wrapped, ok := conn.(*wrapConn); ok {
			routeID = wrapped.routeID
		}
		if !u.trafficControl.Resolve(inboundID, routeID).AllowDatagram(trafficcontrol.Upload, len(data)) {
			metrics.Counter.AddSendUDPDroppedPacket()
			return nil
		}
	}
	return sendPacket(data, dst, conn)
}

// WriteTo sends an already prepared destination, publishing its reverse mapping
// before making the packet visible to the network.
func (u *SourceControl) WriteTo(b []byte, real net.Addr, original netapi.Address, conn net.PacketConn) error {
	if original != nil {
		if u.destinationLeaser != nil {
			if err := u.acquireDestinationLease(u.ctx, original); err != nil {
				return err
			}
			defer u.releaseUnusedDestinationLease(original.Comparable())
		}
		if u.mapper == nil {
			u.mapper = newAddressMapper()
		}
		if err := u.mapper.remember(original, real); err != nil {
			return err
		}
		u.retainDestinationLease(original.Comparable())
	}
	return u.writeAuthorizedPacket(nil, b, real, original, conn)
}

func sendPacket(b []byte, real net.Addr, conn net.PacketConn) error {
	_, err := conn.WriteTo(b, real)
	refreshPacketReadDeadline(conn, udpIdleTimeout())
	return err
}
