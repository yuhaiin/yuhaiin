package dns

import (
	"net"
	"testing"

	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
)

func TestUDP(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("0.0.0.0/32")
	// dns := NewDoU("114.114.114.114:53", subnet, nil)
	dns := NewDoU("1.1.1.1:53", subnet, s5c.Dial("127.0.0.1", "1080", "", ""))
	t.Log(dns.LookupIP("baidu.com"))
	t.Log(dns.LookupIP("google.com"))
	t.Log(dns.LookupIP("www.twitter.com"))
	//t.Log(DNS("223.5.5.5:53", "www.google.com"))
	//t.Log(DNS("114.114.114.114:53", "www.baidu.com"))
}
