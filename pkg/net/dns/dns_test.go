package dns

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
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
		Subnet:     subnet,
	})
}

func TestErrCode(t *testing.T) {
	z := fmt.Errorf("test: %w , %w", errors.New("a"), netapi.NewDNSErrCode(dnsmessage.RCodeRefused))

	x := &netapi.DNSErrCode{}

	fmt.Println(errors.As(z, x))
	t.Log(x)
}
