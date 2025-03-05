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

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	pd "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"golang.org/x/net/dns/dnsmessage"
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

	// t.Run("listen packet", func(t *testing.T) {
	// 	ipv4, ipv6 := tc.(*Tailscale).tsnet.TailscaleIPs()
	// 	t.Log(ipv4, ipv6)

	// 	pc, err := tc.(*Tailscale).tsnet.ListenPacket("udp", net.JoinHostPort(ipv4.String(), "0"))
	// 	assert.NoError(t, err)
	// 	defer pc.Close()

	// 	n, err := pc.WriteTo([]byte("test"), &net.UDPAddr{
	// 		IP:   net.ParseIP("100.100.100.100"),
	// 		Port: 53,
	// 	})
	// 	t.Log(n, err)
	// })

	t.Run("udp", func(t *testing.T) {
		r, err := resolver.New(resolver.Config{
			Dialer: tc,
			Host:   "100.100.100.100:53",
			Type:   pd.Type_udp,
		})
		assert.NoError(t, err)

		for range 3 {
			ips, err := r.Raw(context.TODO(), dnsmessage.Question{
				Name:  dnsmessage.MustNewName("code-server.taild2025.ts.net."),
				Type:  65,
				Class: dnsmessage.ClassINET,
			})
			assert.NoError(t, err)

			t.Log(ips)
		}
	})
}

func TestVersion(t *testing.T) {
	t.Log(version.Long())
	t.Log(version.Short())
}
