package tailscale

import (
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestUnavailableLiteClientFailsClosed(t *testing.T) {
	if _, err := resolveAddr(t.Context(), nil, "tcp", nil); err == nil {
		t.Fatal("uninitialized control client accepted a route")
	}
	if _, err := liteDNSQuery(t.Context(), nil, nil); !errors.Is(err, errTailscaleDNSUnavailable) {
		t.Fatalf("uninitialized MagicDNS = %v", err)
	}
}

func TestDNSPacketMissingQueryHandler(t *testing.T) {
	service := netip.MustParseAddrPort("100.100.100.100:53")
	packet := newDNSPacket(t.Context(), nil, service)
	defer packet.Close()
	if _, err := packet.WriteTo([]byte{0, 1}, net.UDPAddrFromAddrPort(service)); !errors.Is(err, errTailscaleDNSUnavailable) {
		t.Fatalf("WriteTo with missing DNS handler: %v", err)
	}
}
