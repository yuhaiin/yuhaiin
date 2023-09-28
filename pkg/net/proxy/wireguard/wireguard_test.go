package wireguard

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestWireguard(t *testing.T) {
	r, err := New(&protocol.Protocol_Wireguard{
		Wireguard: &protocol.Wireguard{
			SecretKey: "OD0YfReLPYBSL/vV+1JSBPpeBurGFLNA4wQCfD+yDFA=",
			Endpoint: []string{
				"10.0.0.2/32",
			},
			Mtu:        1500,
			NumWorkers: 6,
			Reserved:   []byte{0, 0, 0},
			Peers: []*protocol.WireguardPeerConfig{
				{
					PublicKey: "2HWI3cW1HlAyQk1xiu+4QBL1KISMxSo4VQgCz+wCjmo=",
					Endpoint:  "192.168.122.20:51820",
					AllowedIps: []string{
						"0.0.0.0/0",
					},
				},
			},
		},
	})(nil)

	assert.NoError(t, err)

	hc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				addrd, err := netapi.ParseAddress(statistic.Type_tcp, addr)
				if err != nil {
					return nil, err
				}
				return r.Conn(ctx, addrd)
			},
		},
	}

	t.Run("httpbin", func(t *testing.T) {
		resp, err := hc.Get("https://httpbin.org/ip")
		assert.NoError(t, err)
		defer resp.Body.Close()

		data, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)

		t.Log(string(data))
	})
}
