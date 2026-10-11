package openvpn

import (
	"errors"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestUpstreamFailureNeverDialsDirect(t *testing.T) {
	refused := errors.New("chained proxy refused outer VPN transport")
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			c, err := NewClient(Config{Gateway: "127.0.0.1:1194", Network: network, Username: "alice"}, netapi.NewErrProxy(refused))
			if c != nil {
				_ = c.Close()
				t.Fatal("connected despite upstream failure")
			}
			if !errors.Is(err, refused) {
				t.Fatalf("upstream error lost or bypassed: %v", err)
			}
		})
	}
}
