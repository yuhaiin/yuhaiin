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

	ia, err := ResolveIPAddress(addr, nil)
	require.NoError(t, err)
	t.Log(ia.UDPAddr().Zone)

	z, _ := net.ResolveUDPAddr("udp", "[ff::ff%eth0]:53")
	t.Log(z.String(), z.IP, z.Port, z.Zone)

	addr, err = ParseAddress("tcp", "www.google.com:443")
	require.NoError(t, err)

	ia, err = ResolveIPAddress(addr, resolver.Bootstrap.LookupIP)
	require.NoError(t, err)
	t.Log(ia.UDPAddr(), ia.TCPAddr())
	t.Log(addr)
}
