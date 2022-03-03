package dns

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
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
	_, subnet, _ := net.ParseCIDR("1.1.1.1/32")
	dns := NewDNS("114.114.114.114:53", subnet, nil)
	t.Log(dns.LookupIP("baidu.com"))
	t.Log(dns.LookupIP("google.com"))
	//t.Log(DNS("223.5.5.5:53", "www.google.com"))
	//t.Log(DNS("114.114.114.114:53", "www.baidu.com"))
}

func TestDNS9(t *testing.T) {
	dns := NewDNS("[2a07:a8c0::e2:8bb3]:53", nil, socks5client.NewSocks5Client("127.0.0.1", "1080", "", ""))
	t.Log(dns.LookupIP("www.baidu.com"))
	t.Log(dns.LookupIP("www.twitter.com"))
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

	t.Log(0b11110010&0b1111, 0b0010)
	t.Log(0b11111100&0b1111, 0b1100)
}

func TestDNS6(t *testing.T) {
	t.Log(base64.URLEncoding.EncodeToString(creatRequest("www.example.com", A, false)))
	t.Log(base64.URLEncoding.EncodeToString(creatRequest("www.google.com", A, false)))
	t.Log(base64.URLEncoding.EncodeToString(creatRequest("a.62characterlabel-makes-base64url-distinct-from-standard-base64.example.com", A, false)))
}

func TestDNSResolver(t *testing.T) {
	d := NewDNS("114.114.114.114:53", nil, nil)
	t.Log(d.Resolver().LookupHost(context.Background(), "www.baidu.com"))
	t.Log(d.Resolver().LookupHost(context.Background(), "www.google.com"))
	t.Log(d.Resolver().LookupHost(context.Background(), "www.cloudflare.com"))
	t.Log(d.Resolver().LookupHost(context.Background(), "www.apple.com"))
}

func TestResolverHeader(t *testing.T) {
	d := creatRequest("www.example.com", A, false)
	t.Log(d)
	s := &resolver{
		request: d,
		aswer:   d,
	}

	s.header()
}

func TestResolve(t *testing.T) {
	req := []byte{46, 230, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 7, 98, 114, 111, 119, 115, 101, 114, 4, 112, 105, 112, 101, 4, 97, 114, 105, 97, 9, 109, 105, 99, 114, 111, 115, 111, 102, 116, 3, 99, 111, 109, 0, 0, 1, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 12, 0, 8, 0, 8, 0, 1, 22, 0, 223, 5, 4, 0}
	ans := []byte{46, 230, 129, 128, 0, 1, 0, 3, 0, 0, 0, 1, 7, 98, 114, 111, 119, 115, 101, 114, 4, 112, 105, 112, 101, 4, 97, 114, 105, 97, 9, 109, 105, 99, 114, 111, 115, 111, 102, 116, 3, 99, 111, 109, 0, 0, 1, 0, 1, 192, 12, 0, 5, 0, 1, 0, 0, 13, 58, 0, 40, 7, 98, 114, 111, 119, 115, 101, 114, 6, 101, 118, 101, 110, 116, 115, 4, 100, 97, 116, 97, 14, 116, 114, 97, 102, 102, 105, 99, 109, 97, 110, 97, 103, 101, 114, 3, 110, 101, 116, 0, 192, 61, 0, 5, 0, 1, 0, 0, 0, 43, 0, 32, 20, 115, 107, 121, 112, 101, 100, 97, 116, 97, 112, 114, 100, 99, 111, 108, 99, 117, 115, 49, 50, 8, 99, 108, 111, 117, 100, 97, 112, 112, 192, 96, 192, 113, 0, 1, 0, 1, 0, 0, 0, 6, 0, 4, 13, 89, 202, 241, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0}

	t.Log(Resolve(req, ans))
}
