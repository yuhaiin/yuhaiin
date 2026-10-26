package tailscale

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"tailscale.com/net/dns"
	"tailscale.com/tsd"
	"tailscale.com/tsnet"
)

func TestTailscaleDNSManagerMissing(t *testing.T) {
	if manager, err := tailscaleDNSManager(nil); manager != nil || !errors.Is(err, errTailscaleDNSUnavailable) {
		t.Fatalf("nil system: manager=%v err=%v", manager, err)
	}
	sys := new(tsd.System)
	if manager, err := tailscaleDNSManager(sys); manager != nil || !errors.Is(err, errTailscaleDNSUnavailable) {
		t.Fatalf("unset DNS subsystem: manager=%v err=%v", manager, err)
	}

	// In builds using ts_omit_dns, the Tailscale engine explicitly sets a
	// typed nil *dns.Manager and tsnet.Up can still report Running.
	sys.DNSManager.Set((*dns.Manager)(nil))
	if manager, err := tailscaleDNSManager(sys); manager != nil || !errors.Is(err, errTailscaleDNSUnavailable) {
		t.Fatalf("nil DNS subsystem: manager=%v err=%v", manager, err)
	}

	available := new(tsd.System)
	want := testDNSManager(t)
	available.DNSManager.Set(want)
	if manager, err := tailscaleDNSManager(available); err != nil || manager != want {
		t.Fatalf("available DNS subsystem: manager=%v err=%v", manager, err)
	}
}

func TestUnavailableTailscaleDialer(t *testing.T) {
	// Resolve addresses without requiring a real Tailscale server to start.
	// An unset sys handle must return an error rather than panic.
	server := new(tsnet.Server)
	_, err := resolveAddr(t.Context(), server, "tcp", nil)
	if err == nil {
		t.Fatal("expected error for uninitialized Tailscale system")
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
