package dns

import (
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
