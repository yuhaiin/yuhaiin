package subscr

import (
	"bytes"
	context "context"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	ssClient "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocks"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
)

func TestSsrParse2(t *testing.T) {
	ssr := []string{"ssr://MS4xLjEuMTo1MzphdXRoX2NoYWluX2E6bm9uZTpodHRwX3NpbXBsZTo2YUtkNW9HcDZMcXIvP29iZnNwYXJhbT02YUtkNW9HcDZMcXImcHJvdG9wYXJhbT02YUtkNW9HcDZMcXImcmVtYXJrcz02YUtkNW9HcDZMcXImZ3JvdXA9NmFLZDVvR3A2THFy",
		"ssr://MS4xLjEuMTo1MzphdXRoX2NoYWluX2E6bm9uZTpodHRwX3NpbXBsZTo2YUtkNW9HcDZMcXIvP29iZnNwYXJhbT02YUtkNW9HcDZMcXImcHJvdG9wYXJhbT02YUtkNW9HcDZMcXImcmVtYXJrcz1jMlZqYjI1ayZncm91cD02YUtkNW9HcDZMcXIK",
		"ssr://MS4xLjEuMTo1MzphdXRoX2NoYWluX2E6bm9uZTpodHRwX3NpbXBsZTo2YUtkNW9HcDZMcXIvP29iZnNwYXJhbT02YUtkNW9HcDZMcXImcHJvdG9wYXJhbT02YUtkNW9HcDZMcXImcmVtYXJrcz1jM056YzNOeiZncm91cD1jM056YzNOego",
		"ssr://MjIyLjIyMi4yMjIuMjIyOjQ0MzphdXRoX2FlczEyOF9tZDU6Y2hhY2hhMjAtaWV0ZjpodHRwX3Bvc3Q6ZEdWemRBby8/b2Jmc3BhcmFtPWRHVnpkQW8mcHJvdG9wYXJhbT1kR1Z6ZEFvJnJlbWFya3M9ZEdWemRBbyZncm91cD1kR1Z6ZEFvCg"}

	for x := range ssr {
		log.Println((&shadowsocksr{}).ParseLink([]byte(ssr[x]), "test"))
	}
}

func TestLint(t *testing.T) {
	f, err := os.Open("/node_ssr.txt")
	if err != nil {
		t.Log(err)
	}
	s, err := ioutil.ReadAll(f)
	if err != nil {
		t.Log(err)
	}
	dst, err := DecodeBytesBase64(s)
	if err != nil {
		t.Log(err)
	}
	for _, x := range bytes.Split(dst, []byte("\n")) {
		log.Println((&shadowsocksr{}).ParseLink(x, "test"))
	}
}

func TestConnections(t *testing.T) {
	p := simple.NewSimple("127.0.0.1", "1090")

	z, err := ssClient.NewHTTPOBFS("example.com", "80")(p)
	require.Nil(t, err)
	z, err = ssClient.NewShadowsocks("AEAD_AES_128_GCM", "test", "127.0.0.1", "1090")(z)
	require.Nil(t, err)
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
	require.Nil(t, err)
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	require.Nil(t, err)
	t.Log(string(data))
}

// func TestConnectionSsr(t *testing.T) {
// 	tt := &http.Client{
// 		Transport: &http.Transport{
// 			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
// 				return z.Conn(addr)
// 			},
// 		},
// 	}

// 	dns := dns.NewDNS("1.1.1.1:53", nil, z)
// 	t.Log(dns.LookupIP("www.google.com"))

// 	req := http.Request{
// 		Method: "GET",
// 		URL: &url.URL{
// 			Scheme: "http",
// 			Host:   "ip.sb",
// 		},
// 		Header: make(http.Header),
// 	}
// 	req.Header.Set("User-Agent", "curl/v2.4.1")
// 	resp, err := tt.Do(&req)
// 	if err != nil {
// 		t.Error(err)
// 		t.FailNow()
// 	}
// 	require.Nil(t, err)
// 	defer resp.Body.Close()
// 	data, err := ioutil.ReadAll(resp.Body)
// 	require.Nil(t, err)
// 	t.Log(string(data))
// }
