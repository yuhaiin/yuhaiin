package proxy

import (
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils/resolver"
	"github.com/stretchr/testify/require"
)

func TestAddr(t *testing.T) {
	addr, err := ParseAddress("udp", "[ff::ff%eth0]:53")
	if err != nil {
		t.Fatal(err)
	}

	t.Log(addr.Hostname(), addr.IP(), addr.Port(), addr.Type())

	t.Log(addr.UDPAddr())

	z, _ := net.ResolveUDPAddr("udp", "[ff::ff%eth0]:53")
	t.Log(z.String(), z.IP, z.Port, z.Zone)

	addr, err = ParseAddress("tcp", "www.google.com:443")
	require.NoError(t, err)
	t.Log(addr.UDPAddr())

	t.Log(addr.(*DomainAddr).resolver)
	addr.WithResolver(resolver.Bootstrap)
	t.Log(addr.(*DomainAddr).resolver)

}
