package nat

import (
	"errors"
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestMappingBoundsPreserveActiveAndUnknownPeers(t *testing.T) {
	mapper := newAddressMapper()
	first, _ := netapi.ParseAddressPort("udp", "198.18.0.1", 1)
	for i := range maxCachedDestinations {
		original, _ := netapi.ParseAddressPort("udp", "198.18.0.1", uint16(i+1))
		real := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: i + 1}
		if err := mapper.remember(original, real); err != nil {
			t.Fatal(err)
		}
	}
	overflow, _ := netapi.ParseAddressPort("udp", "198.18.0.1", 2000)
	if err := mapper.remember(overflow, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 2000}); !errors.Is(err, errReverseMappingFull) {
		t.Fatalf("overflow=%v", err)
	}
	if len(mapper.targets) != maxCachedDestinations || mapper.reverseCount != maxCachedDestinations {
		t.Fatal("unbounded cache")
	}
	if got := mapper.replyAddr(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 1}); got.String() != first.String() {
		t.Fatalf("active mapping lost: %s", got)
	}
	unknown := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 99), Port: 5000}
	if err := mapper.remember(unknownAddress(t, unknown), unknown); err != nil {
		t.Fatal(err)
	}
	if got := mapper.replyAddr(unknown); got != unknown {
		t.Fatalf("unsolicited peer changed to %s", got)
	}
}

func unknownAddress(t *testing.T, addr net.Addr) netapi.Address {
	t.Helper()
	parsed, err := netapi.ParseSysAddr(addr)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestMappingAliasCollisionKeepsLastAlias(t *testing.T) {
	mapper := newAddressMapper()
	first, _ := netapi.ParseAddressPort("udp", "198.18.0.1", 443)
	second, _ := netapi.ParseAddressPort("udp", "198.18.0.2", 443)
	remote := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 443}
	if err := mapper.remember(first, remote); err != nil {
		t.Fatal(err)
	}
	if err := mapper.remember(second, remote); err != nil {
		t.Fatal(err)
	}
	if got := mapper.replyAddr(remote); got.String() != second.String() {
		t.Fatalf("collision policy returned %s", got)
	}
	if mapper.reverseCount != 1 {
		t.Fatalf("reverse mappings=%d", mapper.reverseCount)
	}
}
