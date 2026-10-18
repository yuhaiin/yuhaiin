package wireguard

import (
	"encoding/base64"
	"strings"
	"testing"
)

func testWGKey(n byte) string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = n
	}
	return base64.StdEncoding.EncodeToString(key)
}

func testServer() ServerConfig {
	return ServerConfig{
		PrivateKey: testWGKey(1), ListenPort: 51820, Addresses: []string{"10.66.0.1/24", "fd66::1/64"},
		Peers: []ServerPeer{{PublicKey: testWGKey(2), AllowedIPs: []string{"10.66.0.2/32", "fd66::2/128"}}},
	}
}

func TestServerIPC(t *testing.T) {
	ipc, addresses, err := serverIPC(testServer())
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 2 || !strings.Contains(ipc.String(), "listen_port=51820\n") ||
		!strings.Contains(ipc.String(), "allowed_ip=10.66.0.2/32") ||
		!strings.Contains(ipc.String(), "allowed_ip=fd66::2/128") {
		t.Fatalf("unexpected server config: %q %v", ipc.String(), addresses)
	}
}

func TestServerIPCRejectsInvalidPeers(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*ServerConfig)
	}{
		{"bad private key", func(c *ServerConfig) { c.PrivateKey = "invalid" }},
		{"port", func(c *ServerConfig) { c.ListenPort = 0 }},
		{"empty peers", func(c *ServerConfig) { c.Peers = nil }},
		{"bad public key", func(c *ServerConfig) { c.Peers[0].PublicKey = "abc" }},
		{"missing allowed IP", func(c *ServerConfig) { c.Peers[0].AllowedIPs = nil }},
		{"wide allowed IP", func(c *ServerConfig) { c.Peers[0].AllowedIPs = []string{"0.0.0.0/0"} }},
		{"gateway collision", func(c *ServerConfig) { c.Peers[0].AllowedIPs = []string{"10.66.0.1/32"} }},
		{"out of subnet", func(c *ServerConfig) { c.Peers[0].AllowedIPs = []string{"10.67.0.2/32"} }},
		{"duplicate client IP", func(c *ServerConfig) {
			c.Peers = append(c.Peers, ServerPeer{PublicKey: testWGKey(3), AllowedIPs: []string{"10.66.0.2/32"}})
		}},
		{"duplicate public key", func(c *ServerConfig) {
			c.Peers = append(c.Peers, ServerPeer{PublicKey: testWGKey(2), AllowedIPs: []string{"10.66.0.3/32"}})
		}},
		{"invalid PSK", func(c *ServerConfig) { c.Peers[0].PreSharedKey = "not-base64" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testServer()
			tt.modify(&c)
			if _, _, err := serverIPC(c); err == nil {
				t.Fatal("expected invalid configuration to fail")
			}
		})
	}
}
