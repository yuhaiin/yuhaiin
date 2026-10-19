package zerotier

import (
	"encoding/binary"
	"net/netip"
	"testing"

	zt "github.com/yuhaiin/zerotier-go"
)

func TestARPResolveAndReply(t *testing.T) {
	id := zt.NetworkID(0x8056c2e21c000001)
	local := netip.MustParseAddr("10.44.1.2")
	remote := netip.MustParseAddr("10.44.1.3")
	const ownMAC uint64 = 0xaabbccddee01
	const peerMAC uint64 = 0xaabbccddee02
	var frames []zt.Frame
	var injected [][]byte
	b := newEtherBridge(zt.NetworkConfig{
		ID: id, MAC: ownMAC, MTU: 2800,
		Addresses: []netip.Prefix{netip.MustParsePrefix("10.44.1.2/24")},
	}, func(f zt.Frame) { frames = append(frames, f) }, func(p []byte) error {
		injected = append(injected, append([]byte(nil), p...))
		return nil
	})
	ip := make([]byte, 20)
	ip[0] = 0x45
	l, r := local.As4(), remote.As4()
	copy(ip[12:16], l[:])
	copy(ip[16:20], r[:])
	b.outgoing(ip)
	if len(frames) != 1 || frames[0].EtherType != etherARP || frames[0].DestinationMAC != broadcast {
		t.Fatalf("expected ARP broadcast, got %+v", frames)
	}
	request := frames[0].Data
	if netip.AddrFrom4([4]byte(request[24:28])) != remote {
		t.Fatal("ARP request must ask for the destination address")
	}
	response := append([]byte(nil), request...)
	binary.BigEndian.PutUint16(response[6:8], 2)
	peerBytes := macBytes(peerMAC)
	copy(response[8:14], peerBytes[:])
	copy(response[14:18], r[:])
	copy(response[18:24], request[8:14])
	copy(response[24:28], l[:])
	b.incoming(zt.Frame{NetworkID: id, SourceMAC: peerMAC, DestinationMAC: ownMAC, EtherType: etherARP, Data: response})
	if len(frames) != 2 || frames[1].EtherType != etherIPv4 || frames[1].DestinationMAC != peerMAC {
		t.Fatalf("queued IPv4 datagram not flushed: %+v", frames)
	}
	// Respond to a peer's ARP request without asking the host kernel.
	copy(response[8:14], peerBytes[:])
	copy(response[14:18], r[:])
	copy(response[24:28], l[:])
	binary.BigEndian.PutUint16(response[6:8], 1)
	b.incoming(zt.Frame{NetworkID: id, SourceMAC: peerMAC, DestinationMAC: broadcast, EtherType: etherARP, Data: response})
	if len(frames) != 3 || frames[2].EtherType != etherARP || binary.BigEndian.Uint16(frames[2].Data[6:8]) != 2 {
		t.Fatalf("ARP response missing: %+v", frames)
	}
	b.incoming(zt.Frame{NetworkID: id, SourceMAC: peerMAC, EtherType: etherIPv4, Data: append([]byte(nil), ip...)})
	if len(injected) != 1 {
		t.Fatal("IPv4 packet must be delivered to userspace IP stack")
	}
}

func TestIPv6NDPResolution(t *testing.T) {
	id := zt.NetworkID(1234)
	own := netip.MustParseAddr("fd7a::2")
	peer := netip.MustParseAddr("fd7a::3")
	const ownMAC uint64 = 0xaabbccddee01
	const peerMAC uint64 = 0xaabbccddee02
	var frames []zt.Frame
	b := newEtherBridge(zt.NetworkConfig{
		ID: id, MAC: ownMAC, Addresses: []netip.Prefix{netip.MustParsePrefix("fd7a::2/64")},
	}, func(f zt.Frame) { frames = append(frames, f) }, func([]byte) error { return nil })
	ip := make([]byte, 40)
	ip[0], ip[6] = 0x60, 17
	l, r := own.As16(), peer.As16()
	copy(ip[8:24], l[:])
	copy(ip[24:40], r[:])
	b.outgoing(ip)
	if len(frames) != 1 || frames[0].DestinationMAC != solicitedMAC(peer) || frames[0].Data[40] != 135 {
		t.Fatalf("expected NDP neighbor solicitation: %+v", frames)
	}
	advertisement := ndpPacket(peer, own, 136, peer, peerMAC, 0x60000000)
	b.incoming(zt.Frame{NetworkID: id, SourceMAC: peerMAC, DestinationMAC: ownMAC, EtherType: etherIPv6, Data: advertisement})
	if len(frames) != 2 || frames[1].EtherType != etherIPv6 || frames[1].DestinationMAC != peerMAC {
		t.Fatal("NDP advertisement must flush queued IPv6 payload")
	}
	// Reply to a legitimate solicitation for the assigned address.
	solicitation := ndpPacket(peer, solicitedIP(own), 135, own, peerMAC, 0)
	b.incoming(zt.Frame{NetworkID: id, SourceMAC: peerMAC, DestinationMAC: solicitedMAC(own), EtherType: etherIPv6, Data: solicitation})
	if len(frames) != 3 || frames[2].Data[40] != 136 || frames[2].DestinationMAC != peerMAC {
		t.Fatal("the bridge must send a unicast neighbor advertisement")
	}
}

func TestPendingNeighborBufferIsBounded(t *testing.T) {
	id := zt.NetworkID(3)
	b := newEtherBridge(zt.NetworkConfig{ID: id, MAC: 10, Addresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}}, func(zt.Frame) {}, func([]byte) error { return nil })
	for n := 1; n <= 255; n++ {
		ip := make([]byte, 20)
		ip[0] = 0x45
		ip[16], ip[17], ip[18], ip[19] = 10, 0, 1, byte(n)
		for range 16 {
			b.outgoing(ip)
		}
	}
	if len(b.pending) > 128 || len(b.requested) > 128 {
		t.Fatalf("pending ARP state is unbounded: pending=%d requested=%d", len(b.pending), len(b.requested))
	}
	for _, items := range b.pending {
		if len(items) > 8 {
			t.Fatalf("pending datagrams per IP exceeded limit: %d", len(items))
		}
	}
}

func TestManagedRouteUpdatesDoNotReplaceNeighborBridge(t *testing.T) {
	id := zt.NetworkID(5)
	prefix := netip.MustParsePrefix("172.16.0.0/16")
	gateway1 := netip.MustParseAddr("10.0.0.1")
	gateway2 := netip.MustParseAddr("10.0.0.254")
	var sent []zt.Frame
	b := newEtherBridge(zt.NetworkConfig{
		ID: id, MAC: 1, Addresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")},
		Routes: []zt.Route{{Target: prefix, Via: gateway1}},
	}, func(f zt.Frame) { sent = append(sent, f) }, func([]byte) error { return nil })
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	copy(pkt[16:20], []byte{172, 16, 1, 2})
	b.outgoing(pkt)
	if len(sent) != 1 || netip.AddrFrom4([4]byte(sent[0].Data[24:28])) != gateway1 {
		t.Fatal("initial route must ARP for its gateway")
	}
	b.updateRoutes([]zt.Route{{Target: prefix, Via: gateway2}})
	b.outgoing(pkt)
	if len(sent) != 2 || netip.AddrFrom4([4]byte(sent[1].Data[24:28])) != gateway2 {
		t.Fatal("updated route must use its new gateway without replacing the IP stack")
	}
}
