package softether

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func dhcpReply(m macAddr, xid uint32, kind byte) []byte {
	b := buildDHCP(m, xid, 1, netip.Addr{}, netip.Addr{})
	ip := b[14:]
	binary.BigEndian.PutUint16(ip[20:22], 67)
	binary.BigEndian.PutUint16(ip[22:24], 68)
	d := ip[28:]
	d[0] = 2
	copy(d[16:20], []byte{192, 168, 30, 5})
	copy(d[240:], []byte{
		53, 1, kind,
		1, 4, 255, 255, 255, 0,
		3, 4, 192, 168, 30, 1,
		54, 4, 192, 168, 30, 1,
		255,
	})
	return b
}

func TestDHCPLease(t *testing.T) {
	m := macAddr{2, 3, 4, 5, 6, 7}
	const xid = 0x12345678
	for _, kind := range []byte{2, 5, 6} {
		msg, got, ok := parseDHCP(dhcpReply(m, xid, kind), m, xid)
		if !ok || msg != kind || got.ip.String() != "192.168.30.5" ||
			got.router.String() != "192.168.30.1" || got.mask != 24 {
			t.Fatalf("bad DHCP reply kind=%d: %d, %+v, %t", kind, msg, got, ok)
		}
	}
	if _, _, ok := parseDHCP(dhcpReply(m, xid, 2), m, xid+1); ok {
		t.Fatal("accepted a reply with an incorrect DHCP transaction ID")
	}
	if _, _, ok := parseDHCP(dhcpReply(m, xid, 2), macAddr{3, 3, 4, 5, 6, 7}, xid); ok {
		t.Fatal("accepted an incorrect client MAC")
	}
}

func TestDHCPTruncation(t *testing.T) {
	m := macAddr{2, 3, 4, 5, 6, 7}
	b := dhcpReply(m, 1, 5)
	for n := 0; n < len(b); n++ {
		_, _, _ = parseDHCP(b[:n], m, 1)
	}
}

func TestEthernetARP(t *testing.T) {
	m := macAddr{2, 5, 5, 5, 5, 5}
	router := netip.MustParseAddr("192.168.30.1")
	local := netip.MustParseAddr("192.168.30.5")
	b := buildARP(m, local, router, macAddr{}, 1)
	if len(b) != 42 || !broadcastMAC(b[:6]) {
		t.Fatalf("invalid ARP broadcast: %x", b)
	}
	op, from, src, dst, ok := parseARP(b)
	if !ok || op != 1 || from != m || src != local || dst != router {
		t.Fatalf("invalid ARP query: %d %v %v %v %t", op, from, src, dst, ok)
	}
	if _, _, _, _, ok := parseARP(b[:41]); ok {
		t.Fatal("accepted truncated ARP")
	}
}

func TestGatewayAddress(t *testing.T) {
	cases := []struct {
		input, host, endpoint string
		valid bool
	}{
		{"vpn.example.org", "vpn.example.org", "vpn.example.org:443", true},
		{"vpn.example.org:5555", "vpn.example.org", "vpn.example.org:5555", true},
		{"[2001:db8::1]", "2001:db8::1", "[2001:db8::1]:443", true},
		{"https://vpn.example.org", "", "", false},
		{"vpn.example.org/path", "", "", false},
		{"vpn.example.org:0", "", "", false},
	}
	for _, c := range cases {
		host, endpoint, err := gatewayAddress(c.input)
		if (err == nil) != c.valid || (c.valid && (host != c.host || endpoint != c.endpoint)) {
			t.Errorf("gatewayAddress(%q) = %q, %q, %v", c.input, host, endpoint, err)
		}
	}
}
