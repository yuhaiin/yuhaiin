package dns

import (
	"net"
	"testing"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
)

func ExampleNew() {
	_, subnet, err := net.ParseCIDR("1.1.1.1/24")
	if err != nil {
		panic(err)
	}

	New(Config{
		Type:       dns.Type_doh,
		Name:       "cloudflare",
		Host:       "cloudflare-dns.com",
		Servername: "cloudflare-dns.com",
		IPv6:       true,
		Subnet:     subnet,
	})
}

func TestAl(t *testing.T) {
	c := ipResponse{}

	t.Log(unsafe.Alignof(c), unsafe.Sizeof(c), unsafe.Sizeof(c.expireAfter), unsafe.Sizeof(c.ips))
}
