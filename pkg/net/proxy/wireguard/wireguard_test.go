package wireguard

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestWireguard(t *testing.T) {
	t.Skip("requires a real WireGuard peer and external httpbin access")

	r, err := NewClient(Config{
		SecretKey: "OD0YfReLPYBSL/vV+1JSBPpeBurGFLNA4wQCfD+yDFA=",
		Endpoint: []string{
			"10.0.0.2/32",
		},
		MTU:      1500,
		Reserved: []byte{0, 0, 0},
		Peers: []PeerConfig{
			{
				PublicKey: "2HWI3cW1HlAyQk1xiu+4QBL1KISMxSo4VQgCz+wCjmo=",
				Endpoint:  "192.168.122.20:51820",
				AllowedIPs: []string{
					"0.0.0.0/0",
				},
			},
		},
	}, nil)

	assert.NoError(t, err)

	hc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				addrd, err := netapi.ParseAddress("tcp", addr)
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
