package tun2socket

import (
	"net"
	"net/netip"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestDualListen(t *testing.T) {
	v4, v6, port, err := dualStackListen(netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1"))
	assert.NoError(t, err)
	defer v4.Close()
	defer v6.Close()

	t.Log(v4.Addr(), v6.Addr(), port)

	assert.MustEqual(t, v4.Addr().(*net.TCPAddr).Port, v6.Addr().(*net.TCPAddr).Port)
}
