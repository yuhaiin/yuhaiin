package register

import (
	"errors"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/auth"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

type credentialResolverStub struct {
	values map[string]auth.ResolvedCredential
	called []string
}

func (s *credentialResolverStub) ResolveCredential(userID, protocolType string) (auth.ResolvedCredential, error) {
	s.called = append(s.called, userID+":"+protocolType)
	value, ok := s.values[userID+":"+protocolType]
	if !ok {
		return auth.ResolvedCredential{}, errors.New("missing test credential")
	}
	return value, nil
}

func TestResolveProtocolCredentialsCoversManagedProtocols(t *testing.T) {
	resolver := &credentialResolverStub{values: map[string]auth.ResolvedCredential{
		"ss:shadowsocks":   {Password: "ss-resolved"},
		"ssr:shadowsocksr": {Password: "ssr-resolved"},
		"vmess:vmess":      {UUID: "vmess-resolved"},
		"vless:vless":      {UUID: "vless-resolved"},
		"trojan:trojan":    {Password: "trojan-resolved"},
		"socks:socks5":     {Username: "socks-user", Password: "socks-pass"},
		"http:http":        {Username: "http-user", Password: "http-pass"},
		"yuu:yuubinsya":    {Password: "yuu-resolved"},
		"tail:tailscale":   {Token: "tail-resolved"},
		"aead:aead":        {Password: "aead-resolved"},
	}}
	protocols := []contractnode.Protocol{
		{Type: "shadowsocks", Shadowsocks: &contractnode.Shadowsocks{UserID: "ss", Password: "old"}},
		{Type: "shadowsocksr", Shadowsocksr: &contractnode.Shadowsocksr{UserID: "ssr", Password: "old"}},
		{Type: "vmess", Vmess: &contractnode.Vmess{UserID: "vmess", UUID: "old"}},
		{Type: "vless", Vless: &contractnode.Vless{UserID: "vless", UUID: "old"}},
		{Type: "trojan", Trojan: &contractnode.Trojan{UserID: "trojan", Password: "old"}},
		{Type: "socks5", Socks5: &contractnode.Socks5{UserID: "socks", User: "old", Password: "old"}},
		{Type: "http", HTTP: &contractnode.HTTP{UserID: "http", User: "old", Password: "old"}},
		{Type: "yuubinsya", Yuubinsya: &contractnode.Yuubinsya{UserID: "yuu", Password: "old"}},
		{Type: "tailscale", Tailscale: &contractnode.Tailscale{UserID: "tail", AuthKey: "old"}},
		{Type: "aead", AEAD: &contractnode.AEAD{UserID: "aead", Password: "old"}},
	}
	for i := range protocols {
		if err := resolveProtocolCredentials(&protocols[i], resolver); err != nil {
			t.Fatalf("protocol %s: %v", protocols[i].Type, err)
		}
	}
	if protocols[0].Shadowsocks.Password != "ss-resolved" || protocols[1].Shadowsocksr.Password != "ssr-resolved" || protocols[2].Vmess.UUID != "vmess-resolved" || protocols[3].Vless.UUID != "vless-resolved" || protocols[4].Trojan.Password != "trojan-resolved" || protocols[5].Socks5.User != "socks-user" || protocols[5].Socks5.Password != "socks-pass" || protocols[6].HTTP.User != "http-user" || protocols[6].HTTP.Password != "http-pass" || protocols[7].Yuubinsya.Password != "yuu-resolved" || protocols[8].Tailscale.AuthKey != "tail-resolved" || protocols[9].AEAD.Password != "aead-resolved" {
		t.Fatalf("resolved protocols = %+v", protocols)
	}
	if len(resolver.called) != len(protocols) {
		t.Fatalf("resolver calls = %d, want %d", len(resolver.called), len(protocols))
	}
}

func TestResolveProtocolCredentialsRecursesAndClearsLegacyFields(t *testing.T) {
	resolver := &credentialResolverStub{values: map[string]auth.ResolvedCredential{
		"nested:http":  {Username: "nested-user", Password: "nested-pass"},
		"nested:vless": {UUID: "nested-uuid"},
	}}
	protocol := contractnode.Protocol{Type: "network_split", NetworkSplit: &contractnode.NetworkSplit{
		TCP: &contractnode.Protocol{Type: "http", HTTP: &contractnode.HTTP{UserID: "nested", User: "old", Password: "old"}},
		UDP: &contractnode.Protocol{Type: "vless", Vless: &contractnode.Vless{UserID: "nested", UUID: "old"}},
	}}
	if err := resolveProtocolCredentials(&protocol, resolver); err != nil {
		t.Fatal(err)
	}
	if protocol.NetworkSplit.TCP.HTTP.User != "nested-user" || protocol.NetworkSplit.TCP.HTTP.Password != "nested-pass" || protocol.NetworkSplit.UDP.Vless.UUID != "nested-uuid" {
		t.Fatalf("nested resolution failed: %+v", protocol)
	}

	noUser := contractnode.Protocol{Type: "http", HTTP: &contractnode.HTTP{User: "legacy-user", Password: "legacy-pass"}}
	if err := resolveProtocolCredentials(&noUser, resolver); err != nil {
		t.Fatal(err)
	}
	if noUser.HTTP.User != "" || noUser.HTTP.Password != "" {
		t.Fatalf("legacy credentials were not cleared: %+v", noUser.HTTP)
	}
}

func TestResolveProtocolCredentialsRejectsMissingVariant(t *testing.T) {
	resolver := &credentialResolverStub{}
	for _, typ := range []string{"shadowsocks", "vmess", "http", "network_split"} {
		protocol := &contractnode.Protocol{Type: typ}
		if err := resolveProtocolCredentials(protocol, resolver); err == nil {
			t.Fatalf("%s missing variant was accepted", typ)
		}
	}
}

func TestValidateCredentialReferencesChecksNestedAndSkipsInlineKeys(t *testing.T) {
	resolver := &credentialResolverStub{values: map[string]auth.ResolvedCredential{
		"known:http":  {Username: "user", Password: "pass"},
		"known:vless": {UUID: "uuid"},
	}}
	node := contractnode.Node{ID: "node", Chain: []contractnode.Protocol{
		{Type: "network_split", NetworkSplit: &contractnode.NetworkSplit{
			TCP: &contractnode.Protocol{Type: "http", HTTP: &contractnode.HTTP{UserID: "known"}},
			UDP: &contractnode.Protocol{Type: "vless", Vless: &contractnode.Vless{UserID: "known"}},
		}},
		{Type: "wireguard", Wireguard: &contractnode.Wireguard{SecretKey: "inline"}},
		{Type: "cloudflare_warp_masque", CloudflareWarpMasque: &contractnode.CloudflareWarpMasque{PrivateKey: "inline"}},
	}}
	if err := ValidateCredentialReferences(node, resolver); err != nil {
		t.Fatal(err)
	}

	node.Chain[0].NetworkSplit.TCP.HTTP.UserID = "missing"
	if err := ValidateCredentialReferences(node, resolver); err == nil {
		t.Fatal("missing nested user was accepted")
	}
}
