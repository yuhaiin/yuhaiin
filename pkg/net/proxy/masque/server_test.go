package masque

import (
	"crypto/tls"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMasqueServerRequiresAuthentication(t *testing.T) {
	cfg := ServerConfig{
		Listen: "127.0.0.1:0",
		ServerAddresses: []string{"10.88.0.1/32"},
		ClientAddresses: []string{"10.88.0.2/32"},
	}
	_, err := NewServer(cfg, &tls.Config{Certificates: []tls.Certificate{{}}}, nil)
	if err == nil {
		t.Fatal("nil handler unexpectedly accepted")
	}
	// A valid handler is not needed to test config validation: the
	// forbidden empty secret is checked before any socket is opened.
	s := &Server{path: defaultServerPath, authToken: "secret"}
	for _, authorization := range []string{"", "Bearer wrong", "Basic c2VjcmV0"} {
		req := httptest.NewRequest(http.MethodConnect, "https://example.test"+defaultServerPath, nil)
		req.ProtoMajor = 3
		req.Header.Set("Authorization", authorization)
		w := httptest.NewRecorder()
		s.serveHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("auth %q got status %d, want 401", authorization, w.Code)
		}
	}
}

func TestMasqueAddressValidation(t *testing.T) {
	for _, input := range []string{"0.0.0.0/0", "10.0.0.0/24", "224.0.0.1/32", "fd00::/64", "::/0"} {
		if _, err := parseServerPrefixes([]string{input}, true); err == nil {
			t.Errorf("client address %q accepted", input)
		}
	}
	for _, input := range []string{"10.88.0.2/32", "fd88::2/128"} {
		if _, err := parseServerPrefixes([]string{input}, true); err != nil {
			t.Errorf("valid client address %q: %v", input, err)
		}
	}
	if len(fullIPRoutes()) != 2 {
		t.Fatal("missing IPv4/IPv6 route advertisements")
	}
}

func TestMasqueClientValidatesConfig(t *testing.T) {
	_, err := NewClient(contractnode.Masque{}, nil)
	if err == nil || !strings.Contains(err.Error(), "url") {
		t.Fatalf("expected URL validation, got %v", err)
	}
}
