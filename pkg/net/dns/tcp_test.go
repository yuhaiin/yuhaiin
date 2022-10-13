package dns

import (
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
)

func TestTCP(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("1.1.1.1/32")
	dns := New(Config{Type: dns.Type_tcp, Host: "114.114.114.114", Subnet: subnet})
	t.Log(dns.LookupIP("baidu.com"))
	t.Log(dns.LookupIP("google.com"))
	//t.Log(DNS("223.5.5.5:53", "www.google.com"))
	//t.Log(DNS("114.114.114.114:53", "www.baidu.com"))
}
