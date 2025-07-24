package tailscale

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	pd "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
	"tailscale.com/version"
)

func TestTailscale(t *testing.T) {
	configuration.ProxyChain.Set(direct.Default)

	key, err := os.ReadFile(".tsauthkey")
	assert.NoError(t, err)

	tc, err := New(protocol.Tailscale_builder{
		Hostname: proto.String("test"),
		AuthKey:  proto.String(strings.TrimSpace(string(key))),
	}.Build(), nil)
	assert.NoError(t, err)

	t.Run("tcp", func(t *testing.T) {
		hc := http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					ad, err := netapi.ParseAddress(network, addr)
					if err != nil {
						return nil, fmt.Errorf("parse address failed: %w", err)
					}
					return tc.Conn(ctx, ad)
				},
			},
		}

		resp, err := hc.Get("http://5600g.taild2025.ts.net:50051")
		assert.NoError(t, err)
		defer resp.Body.Close()

		_, err = io.Copy(os.Stdout, resp.Body)
		assert.NoError(t, err)
	})

	t.Run("tcpdns", func(t *testing.T) {
		r, err := resolver.New(resolver.Config{
			Dialer: tc,
			Host:   "100.100.100.100:53",
			Type:   pd.Type_tcp,
		})
		assert.NoError(t, err)

		for range 3 {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ips, err := r.Raw(ctx, dns.Question{
				Name:   "code-server.taild2025.ts.net.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			})
			t.Log(ips, err)
		}
	})

	t.Run("udp", func(t *testing.T) {
		r, err := resolver.New(resolver.Config{
			Dialer: tc,
			Host:   "100.100.100.100:53",
			Type:   pd.Type_udp,
		})
		assert.NoError(t, err)

		for range 3 {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ips, err := r.Raw(ctx, dns.Question{
				Name:   "code-server.taild2025.ts.net.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			})
			t.Log(ips, err)
		}
	})
}

func TestVersion(t *testing.T) {
	t.Log(version.Long())
	t.Log(version.Short())
}
