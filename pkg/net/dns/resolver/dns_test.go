package resolver

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	dnsmessage "github.com/miekg/dns"
)

func ExampleNew() {
	subnet, err := netip.ParsePrefix("1.1.1.1/24")
	if err != nil {
		panic(err)
	}

	r, err := New(Config{
		Type:       dns.Type_doh,
		Name:       "cloudflare",
		Host:       "cloudflare-dns.com",
		Servername: "cloudflare-dns.com",
		Subnet:     subnet,
	})
	if err != nil {
		panic(err)
	}
	defer r.Close()

	msg, err := r.Raw(context.Background(), dnsmessage.Question{})
	if err != nil {
		panic(err)
	}

	fmt.Println(msg)
}
