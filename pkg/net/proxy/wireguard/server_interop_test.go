package wireguard

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type inboundEchoHandler struct {
	errors chan error
}

func (*inboundEchoHandler) HandleStream(meta *netapi.StreamMeta) { _ = meta.Src.Close() }
func (*inboundEchoHandler) HandlePing(*netapi.PingMeta) {}

func (h *inboundEchoHandler) HandlePacket(packet *netapi.Packet) {
	defer packet.DecRef()
	payload := bytes.Clone(packet.GetPayload())
	replyFrom := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("198.51.100.7:9000"))
	if _, err := packet.WriteBack(payload, replyFrom); err != nil {
		select {
		case h.errors <- err:
		default:
		}
	}
}

// Exercises two independently encrypted peers, source address ownership,
// promiscuous destination interception, lightweight UDP writeback, and teardown.
// No kernel TUN, routes, namespaces or external WireGuard server are required.
func TestWireGuardInboundUDPInterop(t *testing.T) {
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clients := make([]*ecdh.PrivateKey, 2)
	serverPeers := make([]ServerPeer, 0, len(clients))
	for i := range clients {
		clients[i], err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serverPeers = append(serverPeers, ServerPeer{
			PublicKey: base64.StdEncoding.EncodeToString(clients[i].PublicKey().Bytes()),
			AllowedIPs: []string{fmt.Sprintf("10.66.0.%d/32", i+2)},
		})
	}
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()

	handler := &inboundEchoHandler{errors: make(chan error, 2)}
	server, err := NewServer(ServerConfig{
		PrivateKey: base64.StdEncoding.EncodeToString(serverKey.Bytes()),
		ListenPort: port, Addresses: []string{"10.66.0.1/24"},
		MTU: 1420, Peers: serverPeers,
	}, handler)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	for i, private := range clients {
		t.Run(fmt.Sprintf("peer-%d", i+1), func(t *testing.T) {
			proxy, err := NewClient(Config{
				SecretKey: base64.StdEncoding.EncodeToString(private.Bytes()),
				Endpoint: []string{fmt.Sprintf("10.66.0.%d/32", i+2)},
				MTU: 1420,
				Peers: []PeerConfig{{
					PublicKey: base64.StdEncoding.EncodeToString(serverKey.PublicKey().Bytes()),
					Endpoint: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
					AllowedIPs: []string{"0.0.0.0/0"},
				}},
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			client := proxy.(*Wireguard)
			defer client.Close()
			transport, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer transport.Close()
			client.bind.conn = loopbackTransport{transport}
			client.init()
			if client.device == nil {
				t.Fatal("client wireguard engine did not initialize")
			}
			socket, err := client.net.DialUDP(nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer socket.Close()
			if err := socket.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
				t.Fatal(err)
			}
			destination := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("198.51.100.7:9000"))
			payload := []byte(fmt.Sprintf("encrypted inbound from client %d", i))
			if _, err := socket.WriteTo(payload, destination); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, 512)
			n, from, err := socket.ReadFrom(reply)
			if err != nil {
				t.Fatalf("UDP reply from peer %d: %v", i, err)
			}
			if !bytes.Equal(payload, reply[:n]) || from.(*net.UDPAddr).AddrPort() != destination.AddrPort() {
				t.Fatalf("unexpected UDP response %q from %v", reply[:n], from)
			}
		})
	}
	select {
	case err := <-handler.errors:
		t.Fatalf("writeback: %v", err)
	default:
	}
}
