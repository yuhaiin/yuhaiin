package parser

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestSsrParse(t *testing.T) {
	ssr := []string{
		"ssr://MS4xLjEuMTo1MzphdXRoX2NoYWluX2E6bm9uZTpodHRwX3NpbXBsZTo2YUtkNW9HcDZMcXIvP29iZnNwYXJhbT02YUtkNW9HcDZMcXImcHJvdG9wYXJhbT02YUtkNW9HcDZMcXImcmVtYXJrcz02YUtkNW9HcDZMcXImZ3JvdXA9NmFLZDVvR3A2THFy",
		"ssr://MS4xLjEuMTo1MzphdXRoX2NoYWluX2E6bm9uZTpodHRwX3NpbXBsZTo2YUtkNW9HcDZMcXIvP29iZnNwYXJhbT02YUtkNW9HcDZMcXImcHJvdG9wYXJhbT02YUtkNW9HcDZMcXImcmVtYXJrcz1jMlZqYjI1ayZncm91cD02YUtkNW9HcDZMcXIK",
		"ssr://MS4xLjEuMTo1MzphdXRoX2NoYWluX2E6bm9uZTpodHRwX3NpbXBsZTo2YUtkNW9HcDZMcXIvP29iZnNwYXJhbT02YUtkNW9HcDZMcXImcHJvdG9wYXJhbT02YUtkNW9HcDZMcXImcmVtYXJrcz1jM056YzNOeiZncm91cD1jM056YzNOego",
		"ssr://MjIyLjIyMi4yMjIuMjIyOjQ0MzphdXRoX2FlczEyOF9tZDU6Y2hhY2hhMjAtaWV0ZjpodHRwX3Bvc3Q6ZEdWemRBby8_b2Jmc3BhcmFtPWRHVnpkQW8mcHJvdG9wYXJhbT1kR1Z6ZEFvJnJlbWFya3M9ZEdWemRBbyZncm91cD1kR1Z6ZEFv",
	}

	for x := range ssr {
		t.Log(Parse(node.Type_shadowsocksr, []byte(ssr[x])))
	}
}

func TestConnectionSsr(t *testing.T) {
	p := node.Point_builder{
		Protocols: []*node.Protocol{},
	}

	err := protojson.Unmarshal([]byte(``), p.Build())
	assert.NoError(t, err)
	z, err := register.Dialer(p.Build())
	assert.NoError(t, err)

	tt := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				ad, err := netapi.ParseAddress(network, addr)
				assert.NoError(t, err)
				return z.Conn(ctx, ad)
			},
		},
	}

	dns, err := resolver.New(resolver.Config{
		Type: config.Type_udp,
		Host: "1.1.1.1:53", Dialer: z})
	assert.NoError(t, err)

	t.Log(dns.LookupIP(context.TODO(), "www.google.com"))

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
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	assert.NoError(t, err)
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	t.Log(string(data))
}
