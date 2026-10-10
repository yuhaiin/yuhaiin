package softether

import (
	"bytes"
	"crypto/rand"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/softether/native"
)

func TestIPv6NeighborDiscovery(t *testing.T) {
	mac := macAddr{2, 4, 6, 8, 10, 12}
	local := netip.MustParseAddr("2001:db8:3::5")
	router := netip.MustParseAddr("fe80::1")
	solicit := neighborSolicit(mac, local, router)
	if len(solicit) != 14+40+32 {
		t.Fatalf("unexpected NS size %d", len(solicit))
	}
	typ, target, src, dst, from, ok := parseNeighborMessage(solicit)
	if !ok || typ != 135 || target != router || src != local || from != mac || dst != solicitedNodeMulticast(router) {
		t.Fatalf("bad NS parsing: type=%d target=%v src=%v dst=%v from=%v ok=%v", typ, target, src, dst, from, ok)
	}
	advert := neighborAdvertise(mac, mac, router, local)
	typ, target, src, dst, from, ok = parseNeighborMessage(advert)
	if !ok || typ != 136 || target != router || src != router || dst != local || from != mac {
		t.Fatal("bad NA frame")
	}
	advert[len(advert)-1] ^= 1
	if _, _, _, _, _, ok := parseNeighborMessage(advert); ok {
		t.Fatal("accepted corrupted ICMPv6 checksum")
	}
}

func TestUDPV2AuthenticatedFrameAndTamper(t *testing.T) {
	c, s := &native.UDPClientOptions{}, &native.UDPServerOptions{
		Version: 2, Port: 5555, ClientCookie: 789, ServerCookie: 789,
	}
	if _, err := rand.Read(c.KeyV2[:]); err != nil {
		t.Fatal(err)
	}
	s.KeyV2 = c.KeyV2
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	u, err := newUDPAcceleration(socket, net.IPv4(127, 0, 0, 1), c, s)
	if err != nil {
		t.Fatal(err)
	}
	frame := []byte("test Ethernet frame")
	packet, err := u.seal(frame)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := u.open(packet)
	if err != nil || !bytes.Equal(decoded, frame) {
		t.Fatalf("UDP decoded %q error %v", decoded, err)
	}
	packet[len(packet)-1] ^= 0x01
	if _, err := u.open(packet); err == nil {
		t.Fatal("accepted altered authenticated UDP payload")
	}
}

func TestUDPStabilityRestartsAfterAcknowledgementGap(t *testing.T) {
	sock, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	u := &udpAcceleration{sock: sock}
	now := time.Now()
	u.lastSeen.Store(now.Add(-4 * time.Second).UnixNano())
	u.stableSince.Store(now.Add(-20 * time.Second).UnixNano())

	u.observeAcknowledgement(now)
	if got := u.stableSince.Load(); got != now.UnixNano() {
		t.Fatalf("stableSince = %v, want reset to %v", time.Unix(0, got), now)
	}
}
