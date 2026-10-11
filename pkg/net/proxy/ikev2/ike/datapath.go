package ike

import (
	"errors"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/ikev2/aggfrag"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/ikev2/esp"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/dataplane"
)

// Inbound drop sentinels. Like the esp package's, these are pre-built rather
// than formatted per packet: they are returned on the data path's hot reject
// route, where a flood of stray datagrams must create no garbage.
var (
	errDummyPacket = errors.New("ike: ESP dummy packet (next-header 59)")
	errBadInner    = errors.New("ike: inner packet does not match its declared length")
)

// defaultRoute is every IPv4 destination: what a client's single tunnel to its
// server carries.
func defaultRoute() []netip.Prefix {
	return []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0)}
}

// defaultRoute6 is every IPv6 destination, the v6 half of a full tunnel.
func defaultRoute6() []netip.Prefix {
	return []netip.Prefix{netip.PrefixFrom(netip.IPv6Unspecified(), 0)}
}

// espTunnel adapts an established Child SA to the dataplane.Tunnel interface,
// wrapping an esp.SA plus the routing metadata the pump needs. The tunnel key
// the pump demuxes on is the Child SA's inbound ESP SPI.
//
// peer is atomic because the pump reads it on its outbound goroutine while a
// MOBIKE roam can update it from the IKE control goroutine.
type espTunnel struct {
	espSA  *esp.SA
	inSPI  uint32
	routes []netip.Prefix
	peer   atomic.Pointer[net.UDPAddr]
}

func (t *espTunnel) InboundKey() uint32     { return t.inSPI }
func (t *espTunnel) Routes() []netip.Prefix { return t.routes }
func (t *espTunnel) PeerAddr() *net.UDPAddr { return t.peer.Load() }

// SetPeerAddr updates the ESP return address, but only when it actually changes,
// to keep the inbound data-path hot loop free of needless atomic stores.
func (t *espTunnel) SetPeerAddr(a *net.UDPAddr) {
	if a == nil {
		return
	}
	if cur := t.peer.Load(); cur != nil && cur.Port == a.Port && cur.IP.Equal(a.IP) {
		return
	}
	t.peer.Store(a)
}

// Encapsulate protects one inner IP datagram as ESP (tunnel mode). The inner
// packet's own version nibble sets the ESP next-header — IPv4 (4) or IPv6 (41) —
// so one dual-stack Child SA carries both families.
func (t *espTunnel) Encapsulate(ipPacket []byte) ([]byte, error) {
	return t.espSA.Encapsulate(ipPacket, espNextHeader(ipPacket))
}

// aggfragTunnel is an espTunnel whose Child SA carries RFC 9347 AGGFRAG
// payloads instead of plain inner IP packets.
//
// It is a distinct type rather than a flag on espTunnel because
// dataplane.MultiTunnel is discovered by type assertion: a method defined on
// espTunnel would make EVERY IKEv2 tunnel take the pump's aggregating path,
// including the fifteen protocols-worth of traffic that never negotiated
// AGGFRAG at all.
//
// packer and reasm are each touched by exactly one goroutine -- packer by the
// pump's outbound loop, reasm by its inbound one -- which is what lets them
// hold reusable buffers without a lock.
type aggfragTunnel struct {
	*espTunnel
	packer *aggfrag.Packer
	reasm  *aggfrag.Reassembler
}

func newAggfragTunnel(t *espTunnel) *aggfragTunnel {
	return &aggfragTunnel{espTunnel: t, packer: aggfrag.NewPacker(), reasm: aggfrag.NewReassembler()}
}

// Encapsulate wraps one inner packet in an AGGFRAG payload.
//
// One packet per payload is well-formed -- a payload is a run of blocks, and
// one block is a run of one -- and it is the whole of what fits
// dataplane.Tunnel's one-in-one-out shape. Aggregating SEVERAL packets per
// payload, and the constant-rate transmission that makes IP-TFS a
// traffic-flow-confidentiality mechanism rather than merely a framing one, both
// need a timer-driven sender that the Tunnel interface has nowhere to put. See
// internal/ikev2/aggfrag/README.md for what that leaves undone.
func (t *aggfragTunnel) Encapsulate(ipPacket []byte) ([]byte, error) {
	payload, _ := t.packer.Pack([][]byte{ipPacket}, aggfrag.HeaderLen+len(ipPacket))
	return t.espSA.Encapsulate(payload, aggfrag.ESPNextHeader)
}

// EncapsulatePadded pads the AGGFRAG payload itself rather than adding ESP TFC
// padding around it, because a pad block is what an AGGFRAG receiver already
// knows to discard.
func (t *aggfragTunnel) EncapsulatePadded(ipPacket []byte, minInner int) ([]byte, error) {
	size := max(aggfrag.HeaderLen+len(ipPacket), minInner)
	payload, _ := t.packer.Pack([][]byte{ipPacket}, size)
	return t.espSA.Encapsulate(payload, aggfrag.ESPNextHeader)
}

// AppendEncapsulated is EncapsulatePadded into the pump's buffer. It must be
// defined here rather than inherited: the embedded espTunnel has one too, and
// the promoted method would put a plain inner packet on an SA that negotiated
// AGGFRAG, silently undoing the framing the whole type exists for.
func (t *aggfragTunnel) AppendEncapsulated(dst, ipPacket []byte, minInner int) ([]byte, error) {
	size := max(aggfrag.HeaderLen+len(ipPacket), minInner)
	payload, _ := t.packer.Pack([][]byte{ipPacket}, size)
	return t.espSA.AppendEncapsulated(dst, payload, aggfrag.ESPNextHeader, 0)
}

// DecapsulateMulti opens one ESP packet and returns every inner packet the
// AGGFRAG payload inside it held, implementing dataplane.MultiTunnel. A peer
// that aggregates -- strongSwan does -- puts several in each ESP packet, and
// returning only the first would drop the rest without a word.
func (t *aggfragTunnel) DecapsulateMulti(espPkt []byte, out [][]byte) ([][]byte, error) {
	inner, nextHeader, err := t.espSA.Decapsulate(espPkt)
	if err != nil {
		return out, err
	}
	switch nextHeader {
	case 59:
		return out, errDummyPacket
	case aggfrag.ESPNextHeader:
		pkts, err := t.reasm.Feed(inner)
		if err != nil {
			return out, err
		}
		return append(out, pkts...), nil
	case 4, 41:
		// A peer may still send plain inner packets on an AGGFRAG SA -- the
		// next-header says which, per packet, so both are handled rather than
		// assumed.
		if inner = dataplane.TrimToIP(inner); inner == nil {
			return out, errBadInner
		}
		return append(out, inner), nil
	}
	return out, errBadInner
}

// EncapsulatePadded is Encapsulate with RFC 4303 §2.7 traffic-flow-
// confidentiality padding, implementing dataplane.PaddingTunnel.
func (t *espTunnel) EncapsulatePadded(ipPacket []byte, minInner int) ([]byte, error) {
	return t.espSA.EncapsulatePadded(ipPacket, espNextHeader(ipPacket), minInner)
}

// AppendEncapsulated is EncapsulatePadded into the pump's buffer, implementing
// dataplane.AppendTunnel.
func (t *espTunnel) AppendEncapsulated(dst, ipPacket []byte, minInner int) ([]byte, error) {
	return t.espSA.AppendEncapsulated(dst, ipPacket, espNextHeader(ipPacket), minInner)
}

// espNextHeader picks the ESP next-header for an inner packet from its own
// version nibble — IPv4 (4) or IPv6 (41) — so one dual-stack Child SA carries
// both families.
func espNextHeader(ipPacket []byte) byte {
	if len(ipPacket) > 0 && ipPacket[0]>>4 == 6 {
		return 41
	}
	return 4
}

// Decapsulate opens an ESP packet back to the inner IP datagram, stripping any
// traffic-flow-confidentiality padding (RFC 4303 §2.7) the sender added.
//
// No ESP field delimits TFC padding — only the inner packet's own header does,
// which is exactly what lets a sender pad without the receiver having agreed to
// anything. So the trim happens here, where the next-header value is
// interpreted, rather than in the esp codec which only carries it.
func (t *espTunnel) Decapsulate(espPkt []byte) ([]byte, error) {
	inner, nextHeader, err := t.espSA.Decapsulate(espPkt)
	if err != nil {
		return nil, err
	}
	switch nextHeader {
	case 59: // NoNextHeader: a pure filler packet, with nothing inside at all.
		return nil, errDummyPacket
	case 4, 41: // Tunnel mode, either family.
		if inner = dataplane.TrimToIP(inner); inner == nil {
			return nil, errBadInner
		}
	}
	return inner, nil
}
