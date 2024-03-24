package netlink

import (
	"net"
	"testing"
)

func TestFindProcess(t *testing.T) {
	// 172.19.0.1:55168
	// 10.0.0.103:443
	t.Log(FindProcessName("udp", net.ParseIP("172.19.0.1"), 40498, net.IPv6zero, 0))
}
