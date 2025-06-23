package resolver

import (
	"net/netip"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
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

func TestRemoveIPHint(t *testing.T) {
	data := []byte{
		0, 1, 0,
		0, 1, 0, 6, 2, 104, 51, 2, 104, 50,

		// blow two line are ip hint
		0, 4, 0, 8, 104, 18, 41, 241, 172, 64, 146, 15, // <- ipv4 hint
		0, 6, 0, 32, 38, 6, 71, 0, 68, 0, 0, 0, 0, 0, 0, 0, 104, 18, 41, 241, 38, 6, 71, 0, 68, 0, 0, 0, 0, 0, 0, 0, 172, 64, 146, 15, // <- ipv6 hint

		0, 1, 0, 6, 2, 104, 51, 2, 104, 50,
	}
	except := []byte{
		0, 1, 0,
		0, 1, 0, 6, 2, 104, 51, 2, 104, 50,
		0, 1, 0, 6, 2, 104, 51, 2, 104, 50,
	}
	t.Log(data)
	result, hints := removeIPHintFromResource(dnsmessage.Name{}, data, 60)
	t.Log(result)
	t.Log(hints)

	assert.Equal(t, true, assert.ObjectsAreEqual(except, result))
}

func TestIphintBytes(t *testing.T) {
	data := ipHintParams(
		[]netip.Addr{netip.MustParseAddr("104.18.41.241"), netip.MustParseAddr("172.64.146.15")},
		[]netip.Addr{netip.MustParseAddr("2606:4700:4400::6812:29f1"), netip.MustParseAddr("2606:4700:4400::ac40:920f")},
	)
	origin := []byte{
		0, 1, 0,
		0, 1, 0, 6, 2, 104, 51, 2, 104, 50,
	}

	except := []byte{
		0, 1, 0,
		0, 1, 0, 6, 2, 104, 51, 2, 104, 50,

		// blow two line are ip hint
		0, 4, 0, 8, 104, 18, 41, 241, 172, 64, 146, 15, // <- ipv4 hint
		0, 6, 0, 32, 38, 6, 71, 0, 68, 0, 0, 0, 0, 0, 0, 0, 104, 18, 41, 241, 38, 6, 71, 0, 68, 0, 0, 0, 0, 0, 0, 0, 172, 64, 146, 15, // <- ipv6 hint
	}

	result := appendIPHintIndex(origin, data)

	t.Log(result)
	assert.Equal(t, true, assert.ObjectsAreEqual(except, result))
}
