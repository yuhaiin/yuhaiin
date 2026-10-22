package yuubinsya

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
)

type userEchoHandler struct{ received chan string }

func (h userEchoHandler) HandleStream(meta *netapi.StreamMeta) {
	defer meta.Src.Close()
	id := "legacy"
	if meta.Identity != nil {
		id = meta.Identity.UserID
	}
	h.received <- id
	_, _ = io.Copy(meta.Src, meta.Src)
}
func (h userEchoHandler) HandlePacket(packet *netapi.Packet) {
	defer packet.DecRef()
	id := "legacy"
	if packet.Identity != nil {
		id = packet.Identity.UserID
	}
	h.received <- id
	_, _ = packet.WriteBack(packet.GetPayload(), packet.Dst())
}
func (userEchoHandler) HandlePing(*netapi.PingMeta) {}
func TestYuubinsyaUserAndLegacyCredentialsTCPAndUDP(t *testing.T) {
	ctx, revoke := context.WithCancel(t.Context())
	defer revoke()
	identity := &proxyauth.Identity{UserID: "alice", CredentialID: "phone", Context: ctx}
	verify := func(_ context.Context, _ string, proof []byte) (*proxyauth.Identity, error) {
		if !bytes.Equal(proof, Salt([]byte("user-secret"))) || !identity.Valid() {
			return nil, proxyauth.ErrUnauthorized
		}
		return identity, nil
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		_ = tcp.Close()
		t.Fatal(err)
	}
	lis := netapi.NewListener(tcp, authPacketListener{udp})
	received := make(chan string, 12)
	server, err := NewServer(ServerConfig{Password: "old-secret", Authenticate: verify}, lis, userEchoHandler{received})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	address, _ := netapi.ParseSysAddr(lis.Addr())
	target, _ := netapi.ParseAddress("tcp", "192.0.2.8:80")
	for _, secret := range []string{"user-secret", "old-secret"} {
		for _, uot := range []bool{false, true} {
			parent, err := fixed.NewClient(fixed.Config{Host: address.Hostname(), Port: int32(address.Port())}, nil)
			if err != nil {
				t.Fatal(err)
			}
			client, err := NewClient(Config{Password: secret, UDPOverStream: uot}, parent)
			if err != nil {
				t.Fatal(err)
			}
			stream, err := client.Conn(t.Context(), target)
			if err != nil {
				t.Fatal(err)
			}
			_ = stream.SetDeadline(time.Now().Add(2 * time.Second))
			_, _ = stream.Write([]byte("test"))
			buf := make([]byte, 4)
			if _, err = io.ReadFull(stream, buf); err != nil || string(buf) != "test" {
				t.Fatalf("TCP: %q %v", buf, err)
			}
			_ = stream.Close()
			expected := "alice"
			if secret == "old-secret" {
				expected = "legacy"
			}
			if got := <-received; got != expected {
				t.Fatalf("TCP identity=%s", got)
			}
			packet, err := client.PacketConn(t.Context(), target)
			if err != nil {
				t.Fatal(err)
			}
			_ = packet.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err = packet.WriteTo([]byte("test"), target); err != nil {
				t.Fatal(err)
			}
			buf = make([]byte, 4096)
			n, _, err := packet.ReadFrom(buf)
			if err != nil || string(buf[:n]) != "test" {
				t.Fatalf("UDP uot=%v: %q %v", uot, buf[:n], err)
			}
			_ = packet.Close()
			if got := <-received; got != expected {
				t.Fatalf("UDP identity=%s", got)
			}
			_ = client.Close()
		}
	}
	revoke()
}

type authPacketListener struct{ net.PacketConn }

func (l authPacketListener) Packet(context.Context) (net.PacketConn, error) { return l.PacketConn, nil }
