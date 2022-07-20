package dns

import (
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
)

func TestUDP(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("223.5.5.0/24")
	// dns := NewDoU("114.114.114.114:53", subnet, nil)
	// dns := NewDoU(dns.Config{Host: "1.1.1.1", Subnet: subnet}, s5c.Dial("127.0.0.1", "1080", "", ""))
	// dns := NewDoU(dns.Config{Host: "8.8.8.8", Subnet: subnet}, s5c.Dial("127.0.0.1", "1080", "", ""))
	dns := NewDoU(dns.Config{Host: "119.29.29.29", Subnet: subnet}, s5c.Dial("127.0.0.1", "1080", "", ""))
	t.Log(dns.LookupIP("baidu.com"))
	t.Log(dns.LookupIP("google.com"))
	t.Log(dns.LookupIP("www.twitter.com"))
	t.Log(dns.LookupIP("i2.hdslb.com"))
	//t.Log(DNS("223.5.5.5:53", "www.google.com"))
	//t.Log(DNS("114.114.114.114:53", "www.baidu.com"))
}
