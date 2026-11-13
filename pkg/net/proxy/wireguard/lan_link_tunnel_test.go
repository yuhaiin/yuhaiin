package wireguard

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"net/netip"
	"testing"
)

func TestTunnelConfigValidation(t *testing.T) {
	curve := ecdh.X25519()
	local, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := tunnelConfig{
		PrivateKey: base64.StdEncoding.EncodeToString(local.Bytes()), PeerPublicKey: base64.StdEncoding.EncodeToString(peer.PublicKey().Bytes()),
		LocalIPs: []netip.Addr{netip.MustParseAddr("fd88::1")}, PeerIPs: []netip.Addr{netip.MustParseAddr("fd88::2")}, Routes: []string{"fd80::/64"},
	}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	dual := cfg
	dual.LocalIPs = []netip.Addr{netip.MustParseAddr("10.9.0.2"), netip.MustParseAddr("fd88::1")}
	dual.PeerIPs = []netip.Addr{netip.MustParseAddr("10.9.0.1"), netip.MustParseAddr("fd88::2")}
	dual.Routes = []string{"192.168.1.0/24", "fd80::/64"}
	if err := dual.validate(); err != nil {
		t.Fatalf("dual-stack tunnel rejected: %v", err)
	}
	for name, change := range map[string]func(*tunnelConfig){
		"own public key":   func(c *tunnelConfig) { c.PeerPublicKey = base64.StdEncoding.EncodeToString(local.PublicKey().Bytes()) },
		"duplicate IPs":    func(c *tunnelConfig) { c.PeerIPs = c.LocalIPs },
		"unpaired IPs":     func(c *tunnelConfig) { c.PeerIPs = []netip.Addr{netip.MustParseAddr("10.9.0.1")} },
		"route overlaps":   func(c *tunnelConfig) { c.Routes = []string{"fd88::/64"} },
		"default route":    func(c *tunnelConfig) { c.Routes = []string{"::/0"} },
		"wrong IP family":  func(c *tunnelConfig) { c.Routes = []string{"192.168.1.0/24"} },
		"non-network CIDR": func(c *tunnelConfig) { c.Routes = []string{"fd80::2/64"} },
	} {
		t.Run(name, func(t *testing.T) {
			next := cfg
			change(&next)
			if err := next.validate(); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}
