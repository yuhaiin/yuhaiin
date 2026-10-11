package ike

// Peer listing for the management plane. The ike package deliberately keeps
// client (the public registry) out of its imports, so Peer is a neutral type
// the facade's client.PeerDescriber implementation consumes.

import (
	"fmt"
	"net"
	"time"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// Peer is one live client's identity, assigned address and traffic.
type Peer struct {
	ID         string
	Address    string
	LastActive time.Time
	// Traffic is what this Child SA has actually carried. Zero when the data
	// path cannot report it -- which is a real distinction from "carried
	// nothing", and the facade preserves it.
	Traffic dataplane.TunnelStats
	// HasTraffic is false when the counters are unavailable rather than zero.
	HasTraffic bool
}

// ChildTraffic is an optional DataPath capability: the traffic counters for one
// Child SA, by its inbound SPI.
//
// Optional because DataPath's whole contract is AddChild/RemoveChild, and a
// test double or an alternative data plane satisfies that without a pump behind
// it. Type-asserted rather than added to DataPath so those keep compiling, and
// so a data path that cannot count says so by not implementing it -- which
// Peers reports as "unknown" rather than as zero.
type ChildTraffic interface {
	ChildTraffic(inboundSPI uint32) (dataplane.TunnelStats, bool)
}

// Peers returns one entry per established Child SA, so a panel can show who is
// connected. The ID is the peer's IKE identity (FQDN, email, or IP); Address is
// the tunnel address the server assigned via Config Mode, empty for a peer that
// never asked for one. A peer that never completed IKE_AUTH has no Child SA and
// does not appear.
//
// The registry lock is released before any sa.mu is taken. That ordering is not
// optional: handleSecured holds sa.mu across a whole exchange and calls storeSA
// and deleteSA from under it, so those take s.mu while holding sa.mu. Taking
// them the other way round here -- s.mu.RLock, then sa.mu -- deadlocks against a
// concurrent rekey, and because a pending writer blocks new readers the whole
// listener stops dispatching packets behind it. Close does not clear the
// registry, so a closed server still lists the SAs that were live at close.
func (s *Server) Peers() []Peer {
	s.mu.RLock()
	sas := make([]*IKESA, 0, len(s.byRSPI))
	for _, sa := range s.byRSPI {
		sas = append(sas, sa)
	}
	s.mu.RUnlock()

	traffic, _ := s.cfg.DataPath.(ChildTraffic)

	var out []Peer
	for _, sa := range sas {
		sa.mu.Lock()
		for _, child := range sa.Children {
			p := Peer{
				ID:         peerIDString(sa.PeerID),
				Address:    peerAddress(child),
				LastActive: sa.lastSeen,
			}
			if traffic != nil {
				p.Traffic, p.HasTraffic = traffic.ChildTraffic(child.InboundSPI)
			}
			out = append(out, p)
		}
		sa.mu.Unlock()
	}
	return out
}

// peerAddress is the address an operator wants to see for a Child SA: the
// assigned IPv4, else the IPv6 half of a dual-stack assignment, else empty. It
// exists because net.IP(nil).String() is the literal "<nil>", which is what a
// site-to-site peer -- one that never requested Config Mode -- would otherwise
// show in the panel.
func peerAddress(child *ChildSA) string {
	if len(child.ClientIP) > 0 {
		return child.ClientIP.String()
	}
	if len(child.ClientIP6) > 0 {
		return child.ClientIP6.String()
	}
	return ""
}

// peerIDString renders an ID payload the way an operator reads it: FQDN, RFC
// 822 addr and key-id types are their own bytes; an IP type prints as an
// address; anything else falls back to a hex dump so no identity is blank.
func peerIDString(id payload.IDPayload) string {
	switch id.Type {
	case payload.IDFQDN, payload.IDRFC822, payload.IDKeyID:
		if len(id.Data) > 0 {
			return string(id.Data)
		}
	case payload.IDIPv4Addr, payload.IDIPv6Addr:
		if ip := net.IP(id.Data); len(ip) > 0 {
			return ip.String()
		}
	}
	if len(id.Data) == 0 {
		return fmt.Sprintf("id-type-%d", id.Type)
	}
	return fmt.Sprintf("%x", id.Data)
}
