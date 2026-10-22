package hysteria2

import (
	"context"
	"io"
	"testing"
	"time"

	inbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	node "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
)

func TestHysteria2UserIdentityAndActiveRevocation(t *testing.T) {
	ctx, revoke := context.WithCancel(t.Context())
	defer revoke()
	identity := &proxyauth.Identity{UserID: "alice", CredentialID: "phone", Context: ctx}
	verify := func(_ context.Context, _ string, proof []byte) (*proxyauth.Identity, error) {
		if string(proof) != "user-secret" || !identity.Valid() {
			return nil, proxyauth.ErrUnauthorized
		}
		return identity, nil
	}
	handler := &echoHandler{streams: make(chan *netapi.StreamMeta, 4), packets: make(chan packetMeta, 4)}
	host, ca, _ := newTestServerWithHandler(t, "127.0.0.1:0", "", inbound.Hysteria2Protocol{}, handler, verify)
	client, err := NewClient(node.Hysteria2{Host: host, Auth: "user-secret", TLS: node.TLS{CACert: [][]byte{ca}, ServerNames: []string{"test.example"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	target, _ := netapi.ParseAddress("tcp", "example.com:80")
	stream, err := client.Conn(t.Context(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = stream.Write([]byte("echo"))
	buf := make([]byte, 4)
	if _, err = io.ReadFull(stream, buf); err != nil {
		t.Fatal(err)
	}
	meta := <-handler.streams
	if meta.Identity == nil || meta.Identity.UserID != "alice" {
		t.Fatal("missing stream identity")
	}
	packet, err := client.PacketConn(t.Context(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	_ = packet.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = packet.WriteTo([]byte("echo"), target); err != nil {
		t.Fatal(err)
	}
	if _, _, err = packet.ReadFrom(buf); err != nil {
		t.Fatal(err)
	}
	revoke()
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = stream.Read(buf); err == nil {
		t.Fatal("revoked QUIC session remained usable")
	}
}
