package proxy

import (
	"net"
	"testing"
)

func TestAddr(t *testing.T) {
	addr, err := ParseAddress("udp", "[ff::ff%eth0]:53")
	if err != nil {
		t.Fatal(err)
	}

	t.Log(addr.Hostname(), addr.IP(), addr.Port(), addr.Type())

	z, _ := net.ResolveUDPAddr("udp", "[ff::ff%eth0]:53")
	t.Log(z.String(), z.IP, z.Port, z.Zone)
}
