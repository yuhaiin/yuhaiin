package netlink

import (
	"net"
	"testing"
)

func TestFindProcess(t *testing.T) {
	// 172.19.0.1:55168
	// 10.0.0.103:443
	t.Log(FindProcessName("tcp", net.IPv4(172, 19, 0, 1).To16(), 55168, net.IPv4(10, 0, 0, 103).To16(), 443))
}
