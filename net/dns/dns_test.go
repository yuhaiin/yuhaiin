package dns

import (
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
}
