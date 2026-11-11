package transport

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const PeerTunnelType = "peer_tunnel"

// PeerTunnel pairs a dialing outbound with a LAN-serving inbound.
type PeerTunnel struct {
	Coordinator   string   `json:"coordinator"`
	Token         string   `json:"token" secret:"true"`
	PrivateKey    string   `json:"privateKey" secret:"true"`
	PeerPublicKey string   `json:"peerPublicKey"`
	LocalIP       string   `json:"localIp"`
	PeerIP        string   `json:"peerIp"`
	Routes        []string `json:"routes"`
}

func (PeerTunnel) ProtocolType() string { return PeerTunnelType }

func PeerPairID(key [32]byte) [16]byte {
	hash := sha256.Sum256(key[:])
	return [16]byte(hash[:16])
}

func PeerPairIDString(key [32]byte) string {
	id := PeerPairID(key)
	return hex.EncodeToString(id[:])
}

func DecodePeerKey(s string) ([32]byte, error) {
	var key [32]byte
	n, err := base64.StdEncoding.Decode(key[:], []byte(s))
	if err != nil || n != len(key) || key == [32]byte{} || len(s) != base64.StdEncoding.EncodedLen(len(key)) {
		return key, errors.New("expected a nonzero 32-byte base64 value")
	}
	return key, nil
}

func (c PeerTunnel) Validate() error {
	host, port, err := net.SplitHostPort(c.Coordinator)
	if err != nil || host == "" || strings.ContainsAny(host, " \t\r\n/") {
		return errors.New("peer tunnel: coordinator must be host:port")
	}
	if p, err := strconv.ParseUint(port, 10, 16); err != nil || p == 0 {
		return errors.New("peer tunnel: invalid coordinator port")
	}
	if _, err := DecodePeerKey(c.Token); err != nil {
		return fmt.Errorf("peer tunnel token: %w", err)
	}
	private, err := DecodePeerKey(c.PrivateKey)
	if err != nil {
		return fmt.Errorf("peer tunnel private key: %w", err)
	}
	public, err := DecodePeerKey(c.PeerPublicKey)
	if err != nil {
		return fmt.Errorf("peer tunnel peer public key: %w", err)
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
		return errors.New("peer tunnel: peer must use a different key")
	}
	if _, err := priv.ECDH(peer); err != nil {
		return errors.New("peer tunnel: invalid peer public key")
	}
	local, err := parsePeerIP(c.LocalIP)
	if err != nil {
		return fmt.Errorf("peer tunnel local IP: %w", err)
	}
	remote, err := parsePeerIP(c.PeerIP)
	if err != nil {
		return fmt.Errorf("peer tunnel peer IP: %w", err)
	}
	if local == remote || local.BitLen() != remote.BitLen() {
		return errors.New("peer tunnel: local and peer IPs must be distinct and use the same IP family")
	}
	if len(c.Routes) < 1 || len(c.Routes) > 128 {
		return errors.New("peer tunnel: configure 1 to 128 LAN routes")
	}
	for _, route := range c.Routes {
		p, err := netip.ParsePrefix(route)
		if err != nil || p != p.Masked() || p.Bits() == 0 || p.Addr().BitLen() != local.BitLen() || p.Addr().Is4In6() ||
			p.Addr().IsUnspecified() || p.Addr().IsMulticast() || p.Contains(local) || p.Contains(remote) {
			return fmt.Errorf("peer tunnel: invalid LAN route %q", route)
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
