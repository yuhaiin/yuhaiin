package dns

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"golang.org/x/net/dns/dnsmessage"
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

func TestErrCode(t *testing.T) {
	z := fmt.Errorf("test: %w , %w", errors.New("a"), &dnsErrCode{code: dnsmessage.RCodeFormatError})

	x := &dnsErrCode{}

	fmt.Println(errors.As(z, x))
	t.Log(x)
}
