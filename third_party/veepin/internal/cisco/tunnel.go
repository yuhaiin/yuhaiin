package cisco

// The data path: a tunnel-mode ESP SA adapted to dataplane.Tunnel, so Cisco
// IPsec rides the same pump as every other datagram protocol here.
//
// Nothing in this file is Cisco-specific. It is RFC 4303 tunnel mode, which is
// what the phase-2 negotiation settled on: bare IP inside, the next-header field
// naming the family, and RFC 4303 section 2.7 traffic-flow-confidentiality
// padding available for the shaper to use.

import (
	"errors"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/ikev2/esp"
)

// Inbound drop sentinels, pre-built so the reject route allocates nothing
// however much stray traffic arrives.
var (
	errDummyPacket = errors.New("cisco: ESP dummy packet (next-header 59)")
	errBadInner    = errors.New("cisco: inner packet does not match its declared length")
)

// Tunnel adapts an ESP SA to dataplane.Tunnel.
type Tunnel struct {
	sa     *esp.SA
	inSPI  uint32
	routes []netip.Prefix
	peer   atomic.Pointer[net.UDPAddr]
}

// NewTunnel wraps an SA for the pump. routes are the inner destinations this
// tunnel carries; peer is where ESP is sent.
func NewTunnel(sa *esp.SA, inSPI uint32, routes []netip.Prefix, peer *net.UDPAddr) *Tunnel {
	t := &Tunnel{sa: sa, inSPI: inSPI, routes: routes}
	t.peer.Store(peer)
	return t
}

func (t *Tunnel) InboundKey() uint32     { return t.inSPI }
func (t *Tunnel) Routes() []netip.Prefix { return t.routes }
func (t *Tunnel) PeerAddr() *net.UDPAddr { return t.peer.Load() }

// SetPeerAddr repoints the return path at the address ESP actually arrives
// from, which is how a gateway follows a client whose NAT binding moves. It
// stores only on a real change, to keep the inbound hot loop free of needless
// writes.
func (t *Tunnel) SetPeerAddr(a *net.UDPAddr) {
	if a == nil {
		return
	}
	if cur := t.peer.Load(); cur != nil && cur.Port == a.Port && cur.IP.Equal(a.IP) {
		return
	}
	t.peer.Store(a)
}

// Encapsulate protects one inner IP packet as ESP in tunnel mode.
func (t *Tunnel) Encapsulate(ipPacket []byte) ([]byte, error) {
	return t.sa.Encapsulate(ipPacket, espNextHeader(ipPacket))
}

// EncapsulatePadded is Encapsulate with RFC 4303 section 2.7
// traffic-flow-confidentiality padding, implementing dataplane.PaddingTunnel.
func (t *Tunnel) EncapsulatePadded(ipPacket []byte, minInner int) ([]byte, error) {
	return t.sa.EncapsulatePadded(ipPacket, espNextHeader(ipPacket), minInner)
}

// AppendEncapsulated is EncapsulatePadded into the pump's buffer, implementing
// dataplane.AppendTunnel.
func (t *Tunnel) AppendEncapsulated(dst, ipPacket []byte, minInner int) ([]byte, error) {
	return t.sa.AppendEncapsulated(dst, ipPacket, espNextHeader(ipPacket), minInner)
}

// Decapsulate opens an ESP packet, trimming any TFC padding the sender added.
func (t *Tunnel) Decapsulate(espPkt []byte) ([]byte, error) {
	inner, nextHeader, err := t.sa.Decapsulate(espPkt)
	if err != nil {
		return nil, err
	}
	switch nextHeader {
	case 59: // NoNextHeader: a pure filler packet with nothing inside.
		return nil, errDummyPacket
	case 4, 41:
		if inner = dataplane.TrimToIP(inner); inner == nil {
			return nil, errBadInner
		}
	}
	return inner, nil
}

// espNextHeader names the inner packet's family for the ESP trailer.
func espNextHeader(ipPacket []byte) byte {
	if len(ipPacket) > 0 && ipPacket[0]>>4 == 6 {
		return 41
	}
	return 4
}
