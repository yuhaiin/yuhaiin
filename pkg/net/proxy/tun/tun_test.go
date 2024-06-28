package tun

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
)

func TestCheckTunName(t *testing.T) {
	t.Log(checkTunName(netlink.TunScheme{
		Scheme: "tun",
		Name:   "tun0",
	}))
}
