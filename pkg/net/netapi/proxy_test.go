package netapi

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestAddr(t *testing.T) {
	addr, err := ParseAddress("udp", "[ff::ff%eth0]:53")
	if err != nil {
		t.Fatal(err)
	}

	assert.MustEqual(t, addr.IsFqdn(), false)
	t.Log(addr)

	ip, err := LookupIP(context.TODO(), addr)
	assert.NoError(t, err)
	t.Log(addr.Hostname(), ip, addr.Port(), addr.IsFqdn())

	t.Log(ResolveUDPAddr(context.TODO(), addr))

	z, _ := net.ResolveUDPAddr("udp", "[ff::ff%eth0]:53")
	t.Log(z.String(), z.IP, z.Port, z.Zone)

	addr, err = ParseAddress("tcp", "www.google.com:443")
	assert.NoError(t, err)
	t.Log(ResolveUDPAddr(context.TODO(), addr))
}

func TestError(t *testing.T) {
	x := &net.OpError{
		Op:   "block",
		Net:  "tcp",
		Addr: EmptyAddr,
		Err:  net.UnknownNetworkError("unknown network"),
	}

	y := fmt.Errorf("x: %w", x)

	assert.Equal(t, IsBlockError(y), true)
}
