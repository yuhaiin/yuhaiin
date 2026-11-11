package transport

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestPeerTunnelConfig(t *testing.T) {
	curve := ecdh.X25519()
	local, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token := [32]byte{1}
	cfg := PeerTunnel{
		Coordinator: "discovery.example:51821", Token: base64.StdEncoding.EncodeToString(token[:]),
		PrivateKey: base64.StdEncoding.EncodeToString(local.Bytes()), PeerPublicKey: base64.StdEncoding.EncodeToString(peer.PublicKey().Bytes()),
		LocalIP: "fd88::1", PeerIP: "fd88::2", Routes: []string{"fd80::/64"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*PeerTunnel){
		"port zero":        func(c *PeerTunnel) { c.Coordinator = "discovery.example:0" },
		"invalid token":    func(c *PeerTunnel) { c.Token = "short" },
		"own public key":   func(c *PeerTunnel) { c.PeerPublicKey = base64.StdEncoding.EncodeToString(local.PublicKey().Bytes()) },
		"duplicate IPs":    func(c *PeerTunnel) { c.PeerIP = c.LocalIP },
		"route overlaps":   func(c *PeerTunnel) { c.Routes = []string{"fd88::/64"} },
		"default route":    func(c *PeerTunnel) { c.Routes = []string{"::/0"} },
		"wrong IP family":  func(c *PeerTunnel) { c.Routes = []string{"192.168.1.0/24"} },
		"non-network CIDR": func(c *PeerTunnel) { c.Routes = []string{"fd80::2/64"} },
	} {
		t.Run(name, func(t *testing.T) {
			next := cfg
			change(&next)
			if err := next.Validate(); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}
