package node

import (
	"testing"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

func TestStripRemoteCredentialsClearsManagedFields(t *testing.T) {
	nodes := []contractnode.Node{{Chain: []contractnode.Protocol{
		{Type: "shadowsocks", Shadowsocks: &contractnode.Shadowsocks{UserID: "remote", Password: "secret"}},
		{Type: "shadowsocksr", Shadowsocksr: &contractnode.Shadowsocksr{UserID: "remote", Password: "secret"}},
		{Type: "vmess", Vmess: &contractnode.Vmess{UserID: "remote", UUID: "uuid"}},
		{Type: "vless", Vless: &contractnode.Vless{UserID: "remote", UUID: "uuid"}},
		{Type: "trojan", Trojan: &contractnode.Trojan{UserID: "remote", Password: "secret"}},
		{Type: "socks5", Socks5: &contractnode.Socks5{UserID: "remote", User: "user", Password: "secret"}},
		{Type: "http", HTTP: &contractnode.HTTP{UserID: "remote", User: "user", Password: "secret"}},
		{Type: "yuubinsya", Yuubinsya: &contractnode.Yuubinsya{UserID: "remote", Password: "secret"}},
		{Type: "tailscale", Tailscale: &contractnode.Tailscale{UserID: "remote", AuthKey: "secret"}},
		{Type: "aead", AEAD: &contractnode.AEAD{UserID: "remote", Password: "secret"}},
		{Type: "network_split", NetworkSplit: &contractnode.NetworkSplit{
			TCP: &contractnode.Protocol{Type: "http", HTTP: &contractnode.HTTP{UserID: "nested", User: "nested-user", Password: "nested-secret"}},
			UDP: &contractnode.Protocol{Type: "vmess", Vmess: &contractnode.Vmess{UserID: "nested", UUID: "nested-uuid"}},
		}},
		{Type: "wireguard", Wireguard: &contractnode.Wireguard{SecretKey: "wireguard-key", Peers: []contractnode.WireguardPeer{{PreSharedKey: "peer-psk"}}}},
		{Type: "cloudflare_warp_masque", CloudflareWarpMasque: &contractnode.CloudflareWarpMasque{PrivateKey: "warp-key"}},
	}}}

	stripRemoteCredentials(nodes)
	for _, protocol := range nodes[0].Chain[:10] {
		if managedUserID(protocol) != "" {
			t.Errorf("%s userId was not cleared", protocol.Type)
		}
	}
	nested := nodes[0].Chain[10].NetworkSplit
	if nested.TCP.HTTP.UserID != "" || nested.TCP.HTTP.User != "" || nested.TCP.HTTP.Password != "" || nested.UDP.Vmess.UserID != "" || nested.UDP.Vmess.UUID != "" {
		t.Fatalf("nested credentials were not cleared: %+v", nested)
	}
	if nodes[0].Chain[11].Wireguard.SecretKey != "wireguard-key" || nodes[0].Chain[11].Wireguard.Peers[0].PreSharedKey != "peer-psk" {
		t.Fatalf("wireguard inline keys changed: %+v", nodes[0].Chain[11])
	}
	if nodes[0].Chain[12].CloudflareWarpMasque.PrivateKey != "warp-key" {
		t.Fatalf("warp private key changed: %+v", nodes[0].Chain[12])
	}
}

func TestStripRemoteCredentialsDoesNotPanicOnEmptyProtocolVariant(t *testing.T) {
	nodes := []contractnode.Node{{Chain: []contractnode.Protocol{
		{Type: "shadowsocks"},
		{Type: "network_split", NetworkSplit: &contractnode.NetworkSplit{TCP: &contractnode.Protocol{Type: "http"}}},
	}}}
	stripRemoteCredentials(nodes)
}

func managedUserID(protocol contractnode.Protocol) string {
	switch protocol.Type {
	case "shadowsocks":
		return protocol.Shadowsocks.UserID
	case "shadowsocksr":
		return protocol.Shadowsocksr.UserID
	case "vmess":
		return protocol.Vmess.UserID
	case "vless":
		return protocol.Vless.UserID
	case "trojan":
		return protocol.Trojan.UserID
	case "socks5":
		return protocol.Socks5.UserID
	case "http":
		return protocol.HTTP.UserID
	case "yuubinsya":
		return protocol.Yuubinsya.UserID
	case "tailscale":
		return protocol.Tailscale.UserID
	case "aead":
		return protocol.AEAD.UserID
	default:
		return ""
	}
}
