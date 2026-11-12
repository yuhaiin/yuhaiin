package wireguard

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/contract/transport"
)

// tunnelConfig is the WireGuard side of one LAN Link pairing.
type tunnelConfig struct {
	PrivateKey    string
	PeerPublicKey string
	LocalIP       string
	PeerIP        string
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
	local, err := parsePeerIP(c.LocalIP)
	if err != nil {
		return fmt.Errorf("LAN Link tunnel local IP: %w", err)
	}
	remote, err := parsePeerIP(c.PeerIP)
	if err != nil {
		return fmt.Errorf("LAN Link tunnel peer IP: %w", err)
	}
	if local == remote || local.BitLen() != remote.BitLen() {
		return errors.New("LAN Link tunnel: local and peer IPs must be distinct and use the same IP family")
	}
	if len(c.Routes) < 1 || len(c.Routes) > 128 {
		return errors.New("LAN Link tunnel: configure 1 to 128 LAN routes")
	}
	for _, route := range c.Routes {
		p, err := netip.ParsePrefix(route)
		if err != nil || p != p.Masked() || p.Bits() == 0 || p.Addr().BitLen() != local.BitLen() || p.Addr().Is4In6() ||
			p.Addr().IsUnspecified() || p.Addr().IsMulticast() || p.Contains(local) || p.Contains(remote) {
			return fmt.Errorf("LAN Link tunnel: invalid LAN route %q", route)
		}
	}
	return nil
}

func parsePeerIP(s string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(s)
	if err != nil || !ip.IsGlobalUnicast() || ip.Is4In6() || ip.Zone() != "" {
		return netip.Addr{}, errors.New("expected a unicast IP address")
	}
	return ip, nil
}
