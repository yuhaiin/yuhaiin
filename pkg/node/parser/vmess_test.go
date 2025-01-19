package parser

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"google.golang.org/protobuf/encoding/protojson"
)

//{
//"host":"",
//"path":"",
//"tls":"",
//"verify_cert":true,
//"add":"127.0.0.1",
//"port":0,
//"aid":2,
//"net":"tcp",
//"type":"none",
//"v":"2",
//"ps":"name",
//"id":"cccc-cccc-dddd-aaa-46a1aaaaaa",
//"class":1
//}

func TestGetVmess(t *testing.T) {
	data := "vmess://eyJob3N0Ijoid3d3LmV4YW1wbGUuY29tIiwicGF0aCI6Ii90ZXN0IiwidGxzIjoiIiwidmVyaWZ5X2NlcnQiOnRydWUsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImFpZCI6IjEiLCJuZXQiOiJ3cyIsInR5cGUiOiJub25lIiwidiI6IjIiLCJwcyI6ImV4YW1wbGUiLCJ1dWlkIjoiMmYzYjJiYjktYjJhZS0zOTE5LTk1ZDQtNzAyY2U3YzAyMjYyIiwiY2xhc3MiOjB9Cg=="
	t.Log(Parse(subscribe.Type_vmess, []byte(data)))

	data = "vmess://eyJob3N0Ijoid3d3LmV4YW1wbGUuY29tIiwicGF0aCI6Ii90ZXN0IiwidGxzIjoiIiwidmVyaWZ5X2NlcnQiOnRydWUsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6NDQzLCJhaWQiOjEsIm5ldCI6IndzIiwidHlwZSI6Im5vbmUiLCJ2IjoiMiIsInBzIjoiZXhhbXBsZSIsInV1aWQiOiIyZjNiMmJiOS1iMmFlLTM5MTktOTVkNC03MDJjZTdjMDIyNjIiLCJjbGFzcyI6MH0K"
	t.Log(Parse(subscribe.Type_vmess, []byte(data)))
}

func TestVmess(t *testing.T) {
	z := &point.Point{}

	err := protojson.Unmarshal([]byte(``), z)
	assert.NoError(t, err)

	x, err := register.Dialer(z)
	assert.NoError(t, err)

	tt := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				ad, err := netapi.ParseAddress(network, addr)
				if err != nil {
					return nil, fmt.Errorf("parse address failed: %w", err)
				}
				return x.Conn(ctx, ad)
			},
		},
	}

	req := http.Request{
		Method: "GET",
		URL: &url.URL{
			Scheme: "http",
			Host:   "ip.sb",
		},
		Header: make(http.Header),
	}
	req.Header.Set("User-Agent", "curl/v2.4.1")
	resp, err := tt.Do(&req)
	assert.NoError(t, err)
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	t.Log(string(data))
}
