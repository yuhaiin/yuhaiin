package wireguard

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/conn"
)

type inboundRecordingBind struct {
	conn.Bind
	receive conn.ReceiveFunc
	sent    conn.Endpoint
}

func (b *inboundRecordingBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	return []conn.ReceiveFunc{b.receive}, port, nil
}
func (b *inboundRecordingBind) Send(_ [][]byte, endpoint conn.Endpoint, _ int) error {
	b.sent = endpoint
	return nil
}
func (*inboundRecordingBind) Close() error { return nil }

func TestServerBindEndpointLearning(t *testing.T) {
	first := Endpoint(netip.MustParseAddrPort("127.0.0.1:10001"))
	roamed := Endpoint(netip.MustParseAddrPort("127.0.0.1:10002"))
	var request [148]byte
	binary.LittleEndian.PutUint32(request[:4], 1)
	binary.LittleEndian.PutUint32(request[4:8], 42)
	base := &inboundRecordingBind{Bind: conn.NewDefaultBind()}
	base.receive = func(slab []byte, packets []conn.ReceivedPacket) (int, error) {
		copy(slab, request[:])
		packets[0] = conn.ReceivedPacket{Offset: 0, Size: len(request), Endpoint: first}
		return 1, nil
	}
	bind := newServerBind(base)
	key := [32]byte{0xab}
	peer, err := bind.ParseEndpoint(serverPeerPrefix + hex.EncodeToString(key[:]))
	if err != nil {
		t.Fatal(err)
	}
	data := [][]byte{{4, 0, 0, 0}}
	if err := bind.Send(data, peer, 0); err == nil {
		t.Fatal("unlearned peer must not receive traffic")
	}
	receivers, _, err := bind.Open(51820)
	if err != nil {
		t.Fatal(err)
	}
	defer bind.Close()
	packets := make([]conn.ReceivedPacket, 1)
	slab := make([]byte, 148)
	if _, err := receivers[0](slab, packets); err != nil {
		t.Fatal(err)
	}
	if err := bind.Send(data, peer, 0); err == nil {
		t.Fatal("unauthenticated initiation must not learn an endpoint")
	}
	// Only an engine-generated handshake response may use a pending endpoint.
	response := make([]byte, 20)
	binary.LittleEndian.PutUint32(response[8:12], 2)
	binary.LittleEndian.PutUint32(response[16:20], 42)
	if err := bind.Send([][]byte{response}, peer, 8); err != nil || base.sent != first {
		t.Fatalf("handshake response: endpoint %v, error %v", base.sent, err)
	}
	if len(bind.pending) != 0 {
		t.Fatal("completed handshake was retained")
	}
	// The engine invokes FromPeer only after successful authenticated decryption.
	received := &serverReceiveEndpoint{Endpoint: roamed, owner: bind}
	received.FromPeer(key)
	if err := bind.Send(data, peer, 0); err != nil || base.sent != roamed {
		t.Fatalf("authenticated roaming: endpoint %v, error %v", base.sent, err)
	}
	// A new unauthenticated initiation cannot overwrite the authenticated route.
	if _, err := receivers[0](slab, packets); err != nil {
		t.Fatal(err)
	}
	if err := bind.Send(data, peer, 0); err != nil || base.sent != roamed {
		t.Fatalf("unauthenticated route overwrite: endpoint %v, error %v", base.sent, err)
	}
	// Expired handshakes cannot replace the current endpoint either.
	bind.pending[42] = pendingHandshake{endpoint: first, seen: time.Now().Add(-handshakePendingTTL)}
	if err := bind.Send([][]byte{response}, peer, 8); err != nil || base.sent != roamed {
		t.Fatalf("expired handshake: endpoint %v, error %v", base.sent, err)
	}
}

func TestServerBindPeerKeyCase(t *testing.T) {
	bind := newServerBind(&inboundRecordingBind{Bind: conn.NewDefaultBind()})
	key := [32]byte{0xab}
	peer, err := bind.ParseEndpoint(serverPeerPrefix + strings.ToUpper(hex.EncodeToString(key[:])))
	if err != nil {
		t.Fatal(err)
	}
	endpoint := &serverReceiveEndpoint{Endpoint: Endpoint(netip.MustParseAddrPort("127.0.0.1:1234")), owner: bind}
	endpoint.FromPeer(key)
	if err := bind.Send([][]byte{{4, 0, 0, 0}}, peer, 0); err != nil {
		t.Fatal(err)
	}
}

func TestServerBindConcurrentPeers(t *testing.T) {
	bind := newServerBind(conn.NewDefaultBind())
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			key := [32]byte{byte(i)}
			endpoint := &serverReceiveEndpoint{Endpoint: Endpoint(netip.MustParseAddrPort("127.0.0.1:1234")), owner: bind}
			for range 1000 {
				endpoint.FromPeer(key)
			}
		})
	}
	wg.Wait()
	if len(bind.peers) != 16 {
		t.Fatalf("learned %d peers, want 16", len(bind.peers))
	}
}

func TestServerBindPendingBound(t *testing.T) {
	base := &inboundRecordingBind{Bind: conn.NewDefaultBind()}
	var index uint32
	base.receive = func(slab []byte, packets []conn.ReceivedPacket) (int, error) {
		index++
		binary.LittleEndian.PutUint32(slab[:4], 1)
		binary.LittleEndian.PutUint32(slab[4:8], index)
		packets[0] = conn.ReceivedPacket{Size: 148, Endpoint: Endpoint(netip.MustParseAddrPort("127.0.0.1:1234"))}
		return 1, nil
	}
	bind := newServerBind(base)
	receivers, _, err := bind.Open(51820)
	if err != nil {
		t.Fatal(err)
	}
	slab, packets := make([]byte, 148), make([]conn.ReceivedPacket, 1)
	for range handshakeMaxPending + 128 {
		if _, err := receivers[0](slab, packets); err != nil {
			t.Fatal(err)
		}
		if len(bind.pending) > handshakeMaxPending {
			t.Fatal("unauthenticated handshake table exceeded its limit")
		}
	}
	if err := bind.Close(); err != nil {
		t.Fatal(err)
	}
	if len(bind.pending) != 0 || len(bind.peers) != 0 {
		t.Fatal("closed bind retained peer endpoints")
	}
}
