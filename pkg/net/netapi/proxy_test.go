package netapi

import (
	"context"
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestAddr(t *testing.T) {
	addr, err := ParseAddress(statistic.Type_udp, "[ff::ff%eth0]:53")
	if err != nil {
		t.Fatal(err)
	}

	ip, err := addr.IP(context.TODO())
	assert.NoError(t, err)
	t.Log(addr.Hostname(), ip, addr.Port(), addr.Type())

	t.Log(addr.UDPAddr(context.TODO()))

	z, _ := net.ResolveUDPAddr("udp", "[ff::ff%eth0]:53")
	t.Log(z.String(), z.IP, z.Port, z.Zone)

	addr, err = ParseAddress(statistic.Type_tcp, "www.google.com:443")
	assert.NoError(t, err)
	t.Log(addr.UDPAddr(context.TODO()))
}

func TestOverride(t *testing.T) {
	z, err := ParseAddress(statistic.Type_udp, "1.1.1.1:53")
	assert.NoError(t, err)

	z = z.OverrideHostname("baidu.com")
	t.Log(z)

	z = z.OverrideHostname("1.2.4.8")
	t.Log(z)

	z = z.OverrideHostname("223.5.5.5")
	t.Log(z)
}
