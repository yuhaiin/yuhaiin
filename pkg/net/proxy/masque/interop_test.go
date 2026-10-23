package masque

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// The complete standard HTTP/3 CONNECT-IP handshake runs locally without
// Cloudflare credentials, a host TUN or privileged network setup.
func TestStandardMasqueClientServerConnect(t *testing.T) {
	cert := httptest.NewTLSServer(nil)
	serverTLS := cert.TLS.Clone()
	cert.Close()

	server, err := NewServer(ServerConfig{
		Listen:          "127.0.0.1:0",
		AuthToken:       "test-secret",
		ServerAddresses: []string{"10.88.0.1/32"},
		ClientAddresses: []string{"10.88.0.2/32"},
	}, serverTLS, discardMasqueHandler{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	for _, tc := range []struct {
		name  string
		token string
		valid bool
	}{
		{"wrong-token", "bad-token", false},
		{"valid-token", "test-secret", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxy, err := NewClient(contractnode.Masque{
				Endpoint:           server.packet.LocalAddr().String(),
				URL:                "https://localhost" + defaultServerPath,
				LocalAddresses:     []string{"10.88.0.2/32"},
				BearerToken:        tc.token,
				MTU:                1280,
				InsecureSkipVerify: true,
			}, netapi.NewErrProxy(errors.New("unused bootstrap")))
			if err != nil {
				t.Fatal(err)
			}
			client := proxy.(*Masque)
			defer client.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			conn, err := client.Connect(ctx)
			if tc.valid {
				if err != nil {
					t.Fatalf("valid client could not CONNECT: %v", err)
				}
				defer conn.Close()
				return
			}
			if err == nil {
				conn.Close()
				t.Fatal("invalid bearer token was accepted")
			}
		})
	}
}

type discardMasqueHandler struct{}

func (discardMasqueHandler) HandleStream(*netapi.StreamMeta) {}
func (discardMasqueHandler) HandlePacket(*netapi.Packet)     {}
func (discardMasqueHandler) HandlePing(*netapi.PingMeta)     {}

var _ netapi.Handler = discardMasqueHandler{}
