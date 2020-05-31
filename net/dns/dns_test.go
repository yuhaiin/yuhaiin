package dns

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestDNS(t *testing.T) {
	t.Log(DNS("114.114.114.114:53", "www.baidu.com"))
	t.Log(DNS("114.114.114.114:53", "www.google.com"))
	t.Log(DNS("119.29.29.29:53", "www.baidu.com"))
	t.Log(DNS("119.29.29.29:53", "www.google.com"))
	t.Log(DNS("8.8.8.8:53", "www.baidu.com"))
	t.Log(DNS("8.8.8.8:53", "www.google.com"))
	t.Log(DNS("208.67.222.222:443", "www.baidu.com"))
	t.Log(DNS("208.67.222.222:443", "www.google.com"))
	t.Log(DNS("127.0.0.1:53", "www.baidu.com"))
	t.Log(DNS("127.0.0.1:53", "www.google.com"))
}

func TestDNS2(t *testing.T) {
	t.Log(DNS("114.114.114.114:53", "www.google.com"))
	t.Log(DNS("114.114.114.114:53", "www.baidu.com"))
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
	t.Log(base64.URLEncoding.EncodeToString(creatRequest("www.example.com", A)))
	t.Log(base64.URLEncoding.EncodeToString(creatRequest("www.google.com", A)))
	t.Log(base64.URLEncoding.EncodeToString(creatRequest("a.62characterlabel-makes-base64url-distinct-from-standard-base64.example.com", A)))
}
