package httpapi

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"
)

func TestManagementHTTPS(t *testing.T) {
	for _, tc := range []struct {
		name, peer string
		forwarded  []string
		tls, want  bool
	}{
		{name: "direct remote TLS", peer: "192.0.2.1:1000", tls: true, want: true},
		{name: "TLS overrides forwarded HTTP", peer: "127.0.0.1:1000", forwarded: []string{"http"}, tls: true, want: true},
		{name: "local tunnel", peer: "127.0.0.1:1000", forwarded: []string{"https"}, want: true},
		{name: "IPv6 local tunnel", peer: "[::1]:1000", forwarded: []string{"https"}, want: true},
		{name: "mapped local tunnel", peer: "[::ffff:127.0.0.1]:1000", forwarded: []string{"https"}, want: true},
		{name: "plain local HTTP", peer: "127.0.0.1:1000", want: false},
		{name: "plain local forwarded HTTP", peer: "127.0.0.1:1000", forwarded: []string{"http"}, want: false},
		{name: "remote spoof", peer: "192.0.2.1:1000", forwarded: []string{"https"}, want: false},
		{name: "ambiguous proxy chain", peer: "127.0.0.1:1000", forwarded: []string{"https,http"}, want: false},
		{name: "duplicate headers", peer: "127.0.0.1:1000", forwarded: []string{"https", "https"}, want: false},
		{name: "invalid peer", peer: "localhost", forwarded: []string{"https"}, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://management.example/", nil)
			r.RemoteAddr = tc.peer
			for _, value := range tc.forwarded {
				r.Header.Add("X-Forwarded-Proto", value)
			}
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if got := ManagementHTTPS(r); got != tc.want {
				t.Fatalf("HTTPS=%v want=%v", got, tc.want)
			}
		})
	}
}
