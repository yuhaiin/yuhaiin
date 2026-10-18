package node

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestShareLinkImportWithoutLegacyRegistry(t *testing.T) {
	cases := []struct {
		name, link, protocol string
	}{
		{"trojan", "trojan://secret@server.example:443?sni=example.com#A", "trojan"},
		{"ss", "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:password")) + "@server.example:8388#B", "shadowsocks"},
		{"vmess", "vmess://" + base64.RawStdEncoding.EncodeToString([]byte(`{"add":"server.example","port":"443","id":"00000000-0000-0000-0000-000000000000","aid":"0","security":"auto","ps":"C","net":"tcp","type":"none"}`)), "vmess"},
		{"ssr", "ssr://" + base64.RawURLEncoding.EncodeToString([]byte("server.example:443:origin:aes-128-cfb:plain:"+base64.RawURLEncoding.EncodeToString([]byte("pass"))+"/?remarks="+base64.RawURLEncoding.EncodeToString([]byte("D")))), "shadowsocksr"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseShareURL([]byte(tc.link), "group", "reserve")
			if err != nil {
				t.Fatal(err)
			}
			if got.Group != "group" || got.Name == "" || got.Chain[len(got.Chain)-1].Type != tc.protocol {
				t.Fatalf("unexpected parsed link: %+v", got)
			}
		})
	}
}

func TestShareLinkRejectsInvalidEndpointAndScheme(t *testing.T) {
	for _, link := range []string{
		"trojan://password@server:0",
		"trojan://password@server:65536",
		"unknown://password@server:443",
		"vmess://%%%%",
	} {
		if _, err := parseShareURL([]byte(link), "group", "reserve"); err == nil {
			t.Fatalf("accepted invalid link %q", link)
		}
	}
}

func TestYuhaiinRemoteLinkWithoutLegacySchema(t *testing.T) {
	payload, err := json.Marshal(map[string]any{
		"name": "share",
		"remote": map[string]any{
			"publish": map[string]any{
				"name":     "share",
				"address":  "example.com:8000",
				"path":     "/share",
				"password": "secret",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	link := "yuhaiin://" + base64.RawURLEncoding.EncodeToString(payload)
	parsed, err := parseYuhaiinURL(link)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Remote == nil || parsed.Name != "share" || parsed.Remote.Address != "example.com:8000" {
		t.Fatalf("unexpected parsed remote: %+v", parsed)
	}
}

func TestParserErrorsDoNotLeakPasswords(t *testing.T) {
	secret := "privatepassword"
	result, err := parseShareURL([]byte(fmt.Sprintf("bad://%s@host:443", secret)), "", "")
	if err == nil || strings.Contains(err.Error(), secret) || len(result.Chain) != 0 {
		t.Fatalf("unexpected parse result: %+v, %v", result, err)
	}
}
