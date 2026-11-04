package resolver

import (
	"strconv"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestUDPCacheKey(t *testing.T) {
	for _, test := range []struct {
		id uint16
		name string
		qtype uint16
	}{
		{0, ".", 1},
		{65535, "example.org.", 65535},
		{12, "long.example.net.", 28},
	} {
		question := netapi.DNSQuestion{Name: test.name, Qtype: test.qtype}
		want := strconv.FormatUint(uint64(test.id), 10) + ":" + test.name + "|" + strconv.FormatUint(uint64(test.qtype), 10)
		if got := udpCacheKey(test.id, question); got != want {
			t.Fatalf("udpCacheKey(%d, %q, %d) = %q, want %q", test.id, test.name, test.qtype, got, want)
		}
	}
}

func TestUDPStaticAddressReuse(t *testing.T) {
	addr, err := ParseAddr("udp", "127.0.0.1", "53")
	if err != nil {
		t.Fatal(err)
	}
	u := &udp{addr: addr}
	u.staticAddr, err = u.udpAddr()
	if err != nil {
		t.Fatal(err)
	}
	first, err := u.udpAddr()
	if err != nil {
		t.Fatal(err)
	}
	second, err := u.udpAddr()
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("static UDP destination should be reused")
	}
}
