package dns

import (
	"io/ioutil"
	"net/http"
	"testing"
)

func TestDNSOverHTTPS(t *testing.T) {
	t.Log(DNSOverHTTPS("https://dns.rubyfish.cn/dns-query", "dict.hjenglish.com"))
	t.Log(DNSOverHTTPS("https://dns.rubyfish.cn/dns-query", "i0.hdslb.com"))
	t.Log(DNSOverHTTPS("https://dns.rubyfish.cn/dns-query", "cm.bilibili.com"))
	t.Log(DNSOverHTTPS("https://dns.google/resolve", "dict.hjenglish.com"))
	t.Log(DNSOverHTTPS("https://dns.google/resolve", "i0.hdslb.com"))
	t.Log(DNSOverHTTPS("https://cloudflare-dns.com/dns-query", "cm.bilibili.com"))
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
