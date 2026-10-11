// Package cisco implements Cisco-style IPsec remote access: IKEv1 Aggressive
// Mode with a group pre-shared key, XAuth for the per-user credentials,
// Mode-Config for the address assignment, and a tunnel-mode ESP SA carrying bare
// IP over UDP.
//
// This is the "Cisco IPSec" every desktop and phone has a built-in client for,
// and the exchange vpnc and strongSwan's XAuth plugins speak. The ISAKMP
// machinery all lives in internal/ikev1, which the L2TP profile shares; what is
// here is the remote-access policy around it — the group and user databases, the
// address pool, split tunnelling — and the data path, which is
// internal/ikev2/esp under dataplane.Pump like every other datagram protocol in
// veepin.
package cisco

import (
	"net"
	"net/netip"

	"github.com/xen0bit/veepin/internal/ikev1"
	"github.com/xen0bit/veepin/internal/ikev2/esp"
)

const (
	// nonESPMarkerLen is the 4-octet zero prefix distinguishing an IKE message
	// from an ESP packet on the shared NAT-T port (RFC 3948 section 2.2).
	nonESPMarkerLen = 4
	// DefaultIKEPort carries phase 1 before the NAT-T float; DefaultNATTPort
	// carries IKE and ESP after it (RFC 3947).
	DefaultIKEPort  = 500
	DefaultNATTPort = 4500
)

// newESPSA builds the tunnel-mode ESP SA from a completed IKEv1 exchange. The
// Result already expresses the transform in the IKEv2 IDs the esp package
// consumes and orients the keys and SPIs for the local end.
func newESPSA(r ikev1.Result) *esp.SA {
	return &esp.SA{
		SPIOut: r.OutSPI,
		SPIIn:  r.InSPI,
		Out: esp.Transform{
			EncrID:    r.EncrID,
			EncrKeyLn: r.EncrKeyLn,
			IntegID:   r.IntegID,
			EncKey:    r.OutEncKey,
			IntegKey:  r.OutIntegKey,
		},
		In: esp.Transform{
			EncrID:    r.EncrID,
			EncrKeyLn: r.EncrKeyLn,
			IntegID:   r.IntegID,
			EncKey:    r.InEncKey,
			IntegKey:  r.InIntegKey,
		},
	}
}

// isIKE reports whether a datagram on the shared NAT-T port is an IKE message
// (four leading zero octets) rather than an ESP packet, and returns the message
// with the marker stripped.
//
// The test is safe because an ESP packet cannot look like one: its first four
// octets are the SPI, and RFC 4303 reserves zero.
func isIKE(pkt []byte) ([]byte, bool) {
	if len(pkt) >= nonESPMarkerLen && pkt[0] == 0 && pkt[1] == 0 && pkt[2] == 0 && pkt[3] == 0 {
		return pkt[nonESPMarkerLen:], true
	}
	return nil, false
}

// markIKE prepends the non-ESP marker to an IKE message for the shared port.
func markIKE(msg []byte) []byte {
	out := make([]byte, nonESPMarkerLen+len(msg))
	copy(out[nonESPMarkerLen:], msg)
	return out
}

// NetConfig is the inner addressing Mode-Config assigned, which the caller
// applies to its TUN.
//
// There is no inner gateway address in it, because the protocol has no attribute
// for one: a client reaches the gateway on-link through the netmask it was given
// and everything else through Routes. What the caller needs for its host route is
// the gateway's *outer* address, which it already knows — it dialled it.
type NetConfig struct {
	AssignedIP net.IP
	Netmask    net.IP
	DNS        []net.IP
	Domain     string
	Banner     string
	// Routes are the split-tunnel destinations the gateway named. Empty means
	// the gateway offered no split tunnelling, and the caller decides whether
	// that becomes a default route.
	Routes []netip.Prefix
}

// netConfigFrom converts a Mode-Config assignment into what the caller applies.
func netConfigFrom(r *ikev1.ModeCfgReply) NetConfig {
	if r == nil {
		return NetConfig{}
	}
	nc := NetConfig{
		AssignedIP: r.Address,
		Netmask:    r.Netmask,
		DNS:        r.DNS,
		Domain:     r.Domain,
		Banner:     r.Banner,
	}
	if nc.Netmask == nil {
		// A gateway that assigns an address without a mask means a host address:
		// everything else is reached through the tunnel, not on-link.
		nc.Netmask = net.IP{255, 255, 255, 255}
	}
	for _, n := range r.SplitInclude {
		if p, ok := prefixOf(n); ok {
			nc.Routes = append(nc.Routes, p)
		}
	}
	return nc
}

// prefixOf converts a net.IPNet to a netip.Prefix, reporting false for one that
// has no such representation.
func prefixOf(n *net.IPNet) (netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, bits := n.Mask.Size()
	if bits == 0 {
		return netip.Prefix{}, false // a non-contiguous mask has no prefix length
	}
	return netip.PrefixFrom(addr.Unmap(), ones), true
}

// defaultRoutes is every destination in both families: what a client's single
// tunnel carries when the gateway named no split-tunnel networks.
func defaultRoutes() []netip.Prefix {
	return []netip.Prefix{
		netip.PrefixFrom(netip.IPv4Unspecified(), 0),
		netip.PrefixFrom(netip.IPv6Unspecified(), 0),
	}
}
