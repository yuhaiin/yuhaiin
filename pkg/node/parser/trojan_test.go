package parser

import (
	context "context"
	"crypto/tls"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	tc "github.com/Asutorufa/yuhaiin/pkg/net/proxy/trojan"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/stretchr/testify/require"
)

func TestParseTrojan(t *testing.T) {
	data := "trojan://cb60ba10-1178-3896-ba6e-69ffae322db5@1.1.1.1:443?sni=www.google.com&peer=www.google.com#zxdsdfsdf"
	t.Log(Parse(node.NodeLink_trojan, []byte(data)))
}

func TestTrojan(t *testing.T) {
	p := simple.NewSimple("1.1.1.1", "443", simple.WithTLS(&tls.Config{ServerName: "x.cn"}))

	z, err := tc.NewClient(&node.PointProtocol_Trojan{Trojan: &node.Trojan{Password: "c"}})(p)
	require.NoError(t, err)

	dns := dns.NewDNS("1.1.1.1:53", nil, z)
	t.Log(dns.LookupIP("www.google.com"))

	tt := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return z.Conn(addr)
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
	require.Nil(t, err)
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	require.Nil(t, err)
	t.Log(string(data))
}
