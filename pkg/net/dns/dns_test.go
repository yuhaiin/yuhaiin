package dns

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
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

func TestXxx(t *testing.T) {
	c, err := net.ListenPacket("udp", "")
	assert.NoError(t, err)

	go func() {
		z := make([]byte, 1024)
		_, _, err := c.ReadFrom(z)
		t.Log(err)

		panic(err)
	}()

	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	select {}
}
