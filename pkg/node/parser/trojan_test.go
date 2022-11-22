package parser

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/node/register"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestParseTrojan(t *testing.T) {
	data := "trojan://cb60ba10-1178-3896-ba6e-69ffae322db5@1.1.1.1:443?sni=www.google.com&peer=www.google.com#zxdsdfsdf"
	t.Log(Parse(subscribe.Type_trojan, []byte(data)))
}

func TestTrojan(t *testing.T) {
	p := &point.Point{
		Protocols: []*protocol.Protocol{},
	}

	err := protojson.Unmarshal([]byte(``), p)
	assert.NoError(t, err)
	z, err := register.Dialer(p)
	assert.NoError(t, err)

	dns, err := dns.NewDoU(dns.Config{Host: "1.1.1.1:53", Dialer: z})
	assert.NoError(t, err)
	t.Log(dns.LookupIP("www.google.com"))

	tt := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				ad, err := proxy.ParseAddress(network, addr)
				assert.NoError(t, err)
				return z.Conn(ad)
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
	t.Error(err)
	assert.NoError(t, err)
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	t.Log(string(data))
}
