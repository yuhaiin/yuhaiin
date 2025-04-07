package netlink

import (
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/vishvananda/netlink"
)

func TestFindProcess(t *testing.T) {
	// 172.19.0.1:55168
	// 10.0.0.103:443
	t.Log(FindProcessName("udp", net.ParseIP("172.19.0.1"), 40498, net.IPv6zero, 0))
}

func TestQdisc(t *testing.T) {
	link, err := netlink.LinkByName("lo")
	assert.NoError(t, err)
	a, err := netlink.QdiscList(link)
	assert.NoError(t, err)

	t.Logf("%#v", a[0])
}
