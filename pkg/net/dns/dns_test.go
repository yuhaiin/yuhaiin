package dns

import (
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
)

func ExampleNew() {
	subnet, err := netip.ParsePrefix("1.1.1.1/24")
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
