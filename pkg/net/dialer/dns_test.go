package dialer

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestAddr(t *testing.T) {
	addr, err := netapi.ParseAddress("udp", "[ff::ff%eth0]:53")
	if err != nil {
		t.Fatal(err)
	}

	assert.MustEqual(t, addr.IsFqdn(), false)
	t.Log(addr)

	ip, err := lookupIP(context.TODO(), addr)
	assert.NoError(t, err)
	t.Log(addr.Hostname(), ip, addr.Port(), addr.IsFqdn())

	t.Log(ResolveUDPAddr(context.TODO(), addr))

	z, _ := net.ResolveUDPAddr("udp", "[ff::ff%eth0]:53")
	t.Log(z.String(), z.IP, z.Port, z.Zone)

	addr, err = netapi.ParseAddress("tcp", "www.google.com:443")
	assert.NoError(t, err)
	t.Log(ResolveUDPAddr(context.TODO(), addr))
}

func TestError(t *testing.T) {
	x := &net.OpError{
		Op:   "block",
		Net:  "tcp",
		Addr: netapi.EmptyAddr,
		Err:  net.UnknownNetworkError("unknown network"),
	}

	y := fmt.Errorf("x: %w", x)

	assert.Equal(t, netapi.IsBlockError(y), true)
}

func TestDial8305(t *testing.T) {
	add, err := netapi.ParseDomainPort("tcp", "www.google.com", 443)
	assert.NoError(t, err)
	conn, err := DialHappyEyeballsv2(context.TODO(), add)
	assert.NoError(t, err)
	defer conn.Close()
	t.Log(conn.LocalAddr(), conn.RemoteAddr())
}
