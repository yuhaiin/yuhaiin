package subscr

import (
	context "context"
	"crypto/tls"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	tc "github.com/Asutorufa/yuhaiin/pkg/net/proxy/trojan"
	"github.com/stretchr/testify/require"
)

func TestParseTrojan(t *testing.T) {
	data := "trojan://cb60ba10-1178-3896-ba6e-69ffae322db5@1.1.1.1:443?sni=www.google.com&peer=www.google.com#zxdsdfsdf"
	t.Log((&trojan{}).ParseLink([]byte(data)))
}

func TestTrojan(t *testing.T) {
	p := simple.NewSimple("1.1.1.1", "443", simple.WithTLSConfig(&tls.Config{
		ServerName: "example.com",
	}))

	z, err := tc.NewClient("cbadadad10-2222-3adada-aada6e-adadadada")(p)
	require.NoError(t, err)

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
