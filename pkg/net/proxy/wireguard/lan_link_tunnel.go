package wireguard

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/Asutorufa/yuhaiin/pkg/contract/transport"
)

// tunnelConfig is the WireGuard side of one LAN Link pairing. LocalIPs and
// PeerIPs pair up by index, one per IP family.
type tunnelConfig struct {
	PrivateKey    string
	PeerPublicKey string
	LocalIPs      []netip.Addr
	PeerIPs       []netip.Addr
	Routes        []string
}

func (c tunnelConfig) validate() error {
	private, err := transport.DecodePeerKey(c.PrivateKey)
	if err != nil {
		return fmt.Errorf("LAN Link tunnel private key: %w", err)
	}
	public, err := transport.DecodePeerKey(c.PeerPublicKey)
	if err != nil {
		return fmt.Errorf("LAN Link tunnel peer public key: %w", err)
	}
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(private[:])
	if err != nil {
		return err
	}
	peer, err := curve.NewPublicKey(public[:])
	if err != nil {
		return err
	}
	if priv.PublicKey().Equal(peer) {
		return errors.New("LAN Link tunnel: peer must use a different key")
	}
	if _, err := priv.ECDH(peer); err != nil {
		return errors.New("LAN Link tunnel: invalid peer public key")
	}
	if len(c.LocalIPs) == 0 || len(c.LocalIPs) > 2 || len(c.LocalIPs) != len(c.PeerIPs) {
		return errors.New("LAN Link tunnel: expected one local and one peer IP per address family")
	}
	for i, local := range c.LocalIPs {
		remote := c.PeerIPs[i]
		if !validPeerIP(local) || !validPeerIP(remote) {
			return errors.New("LAN Link tunnel: expected unicast tunnel IP addresses")
		}
		if local == remote || local.BitLen() != remote.BitLen() || (i > 0 && local.BitLen() == c.LocalIPs[0].BitLen()) {
			return errors.New("LAN Link tunnel: local and peer IPs must be distinct and pair up by IP family")
		}
	}
	if len(c.Routes) < 1 || len(c.Routes) > 128 {
		return errors.New("LAN Link tunnel: configure 1 to 128 LAN routes")
	}
	for _, route := range c.Routes {
		p, err := netip.ParsePrefix(route)
		if err != nil || p != p.Masked() || p.Bits() == 0 || p.Addr().Is4In6() || p.Addr().IsUnspecified() || p.Addr().IsMulticast() ||
			!slices.ContainsFunc(c.LocalIPs, func(a netip.Addr) bool { return a.BitLen() == p.Addr().BitLen() }) ||
			slices.ContainsFunc(c.LocalIPs, p.Contains) || slices.ContainsFunc(c.PeerIPs, p.Contains) {
			return fmt.Errorf("LAN Link tunnel: invalid LAN route %q", route)
		}
	}
	return nil
}

func validPeerIP(ip netip.Addr) bool {
	return ip.IsValid() && ip.IsGlobalUnicast() && !ip.Is4In6() && ip.Zone() == ""
}
