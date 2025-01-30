package wireguard

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"google.golang.org/protobuf/proto"
)

func TestWireguard(t *testing.T) {
	r, err := NewClient(protocol.Wireguard_builder{
		SecretKey: proto.String("OD0YfReLPYBSL/vV+1JSBPpeBurGFLNA4wQCfD+yDFA="),
		Endpoint: []string{
			"10.0.0.2/32",
		},
		Mtu:      proto.Int32(1500),
		Reserved: []byte{0, 0, 0},
		Peers: []*protocol.WireguardPeerConfig{
			protocol.WireguardPeerConfig_builder{
				PublicKey: proto.String("2HWI3cW1HlAyQk1xiu+4QBL1KISMxSo4VQgCz+wCjmo="),
				Endpoint:  proto.String("192.168.122.20:51820"),
				AllowedIps: []string{
					"0.0.0.0/0",
				},
			}.Build(),
		},
	}.Build(), nil)

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
