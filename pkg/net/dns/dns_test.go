package dns

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	socks5client "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
)

func TestDNS(t *testing.T) {
	//t.Log(DNS("114.114.114.114:53", "www.baidu.com"))
	//t.Log(DNS("114.114.114.114:53", "www.google.com"))
	//t.Log(DNS("119.29.29.29:53", "www.baidu.com"))
	//t.Log(DNS("119.29.29.29:53", "www.google.com"))
	//t.Log(DNS("8.8.8.8:53", "www.baidu.com"))
	//t.Log(DNS("8.8.8.8:53", "www.google.com"))
	//t.Log(DNS("208.67.222.222:443", "www.baidu.com"))
	//t.Log(DNS("208.67.222.222:443", "www.google.com"))
	//t.Log(DNS("127.0.0.1:53", "www.baidu.com"))
	//t.Log(DNS("127.0.0.1:53", "www.google.com"))
}

func TestDNS2(t *testing.T) {
	dns := NewNormalDNS("114.114.114.114:53", nil)
	t.Log(dns.LookupIP("baidu.com"))
	t.Log(dns.LookupIP("google.com"))
	//t.Log(DNS("223.5.5.5:53", "www.google.com"))
	//t.Log(DNS("114.114.114.114:53", "www.baidu.com"))
}

func TestDNS9(t *testing.T) {
	dns := NewNormalDNS("1.1.1.1:53", nil)
	dns.SetProxy(socks5client.NewSocks5Client("127.0.0.1", "1080", "", ""))
	t.Log(dns.LookupIP("www.baidu.com"))
	t.Log(dns.LookupIP("google.com")) // without proxy [93.46.8.90] <nil>, with proxy [172.217.27.78] <nil>
}

func TestDNS3(t *testing.T) {
	t.Log(0b10000001)
	t.Log(fmt.Sprintf("%08b", 0b00000011)[4:])
}

func TestDNS4(t *testing.T) {
	r := []byte{1}
	s := "a"
	copy(r[:], s)
	t.Log(r)
}

func TestDNS5(t *testing.T) {
	qr := byte(1)
	opCode := byte(0)
	aa := byte(1)
	tc := byte(0)
	rd := byte(1)

	t.Log(fmt.Sprintf("%08b", qr<<7+opCode<<3+aa<<2+tc<<1+rd))

	ra := byte(0)
	z := byte(0b100)
	rcode := byte(0b0000)
	//ra2rCode := []byte{0b00000000} // ra: 0 z:000 rcode: 0000 => bit: 00000000 -> 0
	//qr2rCode := []byte{qr<<7 + opCode<<2 + aa<<1 + tc, ra<<7 + z<<4 + rcode}
	t.Log(fmt.Sprintf("%08b", ra<<7+z<<4+rcode))
}

func TestDNS6(t *testing.T) {
	t.Log(base64.URLEncoding.EncodeToString(creatRequest("www.example.com", A, false)))
	t.Log(base64.URLEncoding.EncodeToString(creatRequest("www.google.com", A, false)))
	t.Log(base64.URLEncoding.EncodeToString(creatRequest("a.62characterlabel-makes-base64url-distinct-from-standard-base64.example.com", A, false)))
}

func TestDNSResolver(t *testing.T) {
	d := NewNormalDNS("114.114.114.114:53", nil)
	t.Log(d.Resolver().LookupHost(context.Background(), "www.baidu.com"))
	t.Log(d.Resolver().LookupHost(context.Background(), "www.google.com"))
	t.Log(d.Resolver().LookupHost(context.Background(), "www.cloudflare.com"))
	t.Log(d.Resolver().LookupHost(context.Background(), "www.apple.com"))
}
