package dns

import (
	"context"
	"io/ioutil"
	"net"
	"net/http"
	"testing"

	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
)

func TestDNSOverHTTPS(t *testing.T) {
	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return s5c.Dial("127.0.0.1", "1080", "", "").Conn(addr)
	}
	t.Log(DOHJsonAPI("https://dns.rubyfish.cn/dns-query", "dict.hjenglish.com", dialContext))
	t.Log(DOHJsonAPI("https://dns.rubyfish.cn/dns-query", "i0.hdslb.com", nil))
	t.Log(DOHJsonAPI("https://dns.rubyfish.cn/dns-query", "cm.bilibili.com", nil))
	t.Log(DOHJsonAPI("https://dns.google/resolve", "dict.hjenglish.com", dialContext))
	t.Log(DOHJsonAPI("https://dns.google/resolve", "i0.hdslb.com", dialContext))
	t.Log(DOHJsonAPI("https://cloudflare-dns.com/dns-query", "cm.bilibili.com", nil))
}

func TestC(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://cloudflare-dns.com/dns-query"+"?dns="+"q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB", nil)
	req.Header.Set("accept", "application/dns-message")
	//res, err := http.Get("https://cloudflare-dns.com/dns-query"+"?dns="+base64.URLEncoding.EncodeToString([]byte("cm.bilibili.com")))
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		t.Log(err)
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Log("Read error", err)
	}
	t.Log(string(body))
}
