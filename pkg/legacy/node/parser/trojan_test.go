package parser_test

import (
	"context"
	"encoding/json/v2"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"

	legacymigrate "github.com/Asutorufa/yuhaiin/pkg/legacy/migrate"
	"github.com/Asutorufa/yuhaiin/pkg/legacy/node/parser"

	"github.com/Asutorufa/yuhaiin/pkg/legacy/schema/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestParseTrojan(t *testing.T) {
	data := "trojan://cb60ba10-1178-3896-ba6e-69ffae322db5@1.1.1.1:443?sni=www.google.com&peer=www.google.com#zxdsdfsdf"
	t.Log(parser.Parse(node.Type_trojan, []byte(data)))
}

func TestTrojan(t *testing.T) {
	t.Skip("requires real proxy configuration plus external DNS and ip.sb access")

	p := node.Point_builder{
		Protocols: []*node.Protocol{},
	}

	err := json.Unmarshal([]byte(`{}`), p.Build())
	assert.NoError(t, err)
	contractNode, _, err := legacymigrate.ConvertLegacyNode(p.Build())
	assert.NoError(t, err)
	z, err := register.ContractDialer(contractNode)
	assert.NoError(t, err)

	dns, err := resolver.New(resolver.Config{Host: "1.1.1.1:53", Dialer: z, Type: "udp"})
	assert.NoError(t, err)
	t.Log(dns.LookupIP(context.TODO(), "www.google.com"))

	tt := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				ad, err := netapi.ParseAddress(network, addr)
				assert.NoError(t, err)
				return z.Conn(ctx, ad)
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
