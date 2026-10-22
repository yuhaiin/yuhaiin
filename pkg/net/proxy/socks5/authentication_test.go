package socks5

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

type authenticatedEcho struct{ identities chan string }

func (h authenticatedEcho) HandleStream(meta *netapi.StreamMeta) {
	defer meta.Src.Close()
	id := "legacy"
	if meta.Identity != nil {
		id = meta.Identity.UserID
	}
	h.identities <- id
	_, _ = io.Copy(meta.Src, meta.Src)
}
func (h authenticatedEcho) HandlePacket(packet *netapi.Packet) {
	defer packet.DecRef()
	id := "legacy"
	if packet.Identity != nil {
		id = packet.Identity.UserID
	}
	h.identities <- id
	_, _ = packet.WriteBack(packet.GetPayload(), packet.Dst())
}
func (authenticatedEcho) HandlePing(*netapi.PingMeta) {}

func authSOCKS(t *testing.T, address, user, password string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write([]byte{5, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	var response [2]byte
	if _, err = io.ReadFull(conn, response[:]); err != nil || response != [2]byte{5, 2} {
		t.Fatalf("method: %v %v", response, err)
	}
	request := append([]byte{1, byte(len(user))}, user...)
	request = append(request, byte(len(password)))
	request = append(request, password...)
	_, _ = conn.Write(request)
	if _, err = io.ReadFull(conn, response[:]); err != nil || response != [2]byte{1, 0} {
		t.Fatalf("auth: %v %v", response, err)
	}
	return conn
}
func associate(t *testing.T, conn net.Conn) netapi.Address {
	t.Helper()
	_, err := conn.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	var response [3]byte
	if _, err = io.ReadFull(conn, response[:]); err != nil || response != [3]byte{5, 0, 0} {
		t.Fatalf("associate: %v %v", response, err)
	}
	address, err := tools.ResolveAddr(conn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.PutBytes(address)
	return address.Address("udp")
}

func TestUserSOCKSUDPAssociationIsolationAndRevocation(t *testing.T) {
	aliceCtx, revoke := context.WithCancel(t.Context())
	defer revoke()
	identities := map[string]*proxyauth.Identity{"alice": {UserID: "alice", CredentialID: "phone", Context: aliceCtx}, "bob": {UserID: "bob", CredentialID: "laptop", Context: t.Context()}}
	verify := func(_ context.Context, user string, proof []byte) (*proxyauth.Identity, error) {
		id := identities[user]
		if id == nil || string(proof) != "secret-"+user || !id.Valid() {
			return nil, proxyauth.ErrUnauthorized
		}
		return id, nil
	}
	lis, err := fixed.NewServer(fixed.ServerConfig{Host: "127.0.0.1:0", Control: fixed.ControlAll})
	if err != nil {
		t.Fatal(err)
	}
	if err = lis.(interface{ Bind() error }).Bind(); err != nil {
		t.Fatal(err)
	}
	received := make(chan string, 16)
	server, err := NewServer(ServerConfig{Authenticate: verify, Username: "old", Password: "password", UDP: true}, lis, authenticatedEcho{received})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	a := authSOCKS(t, lis.Addr().String(), "alice", "secret-alice")
	relayA := associate(t, a)
	b := authSOCKS(t, lis.Addr().String(), "bob", "secret-bob")
	relayB := associate(t, b)
	if relayA.Port() == relayB.Port() {
		t.Fatal("users share a UDP relay port")
	}
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	target, _ := netapi.ParseAddress("udp", "192.0.2.5:1234")
	send := func(relay net.Addr, want string) {
		t.Helper()
		relayAddress, err := net.ResolveUDPAddr("udp", relay.String())
		if err != nil {
			t.Fatal(err)
		}
		client := yuubinsya.NewAuthPacketConn(packet).WithSocks5Prefix(true).WithRealTarget(relayAddress)
		_ = packet.SetDeadline(time.Now().Add(time.Second))
		if _, err := client.WriteTo([]byte("echo"), target); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 256)
		n, _, err := client.ReadFrom(buf)
		if err != nil || string(buf[:n]) != "echo" {
			t.Fatalf("echo %q: %v", buf[:n], err)
		}
		select {
		case got := <-received:
			if got != want {
				t.Fatalf("identity=%s want=%s", got, want)
			}
		case <-time.After(time.Second):
			t.Fatal("no identity")
		}
	}
	send(relayA, "alice")
	send(relayB, "bob")
	// Raw datagrams sent to the legacy shared port must not bypass authentication.
	shared, _ := lis.Packet(t.Context())
	raw := yuubinsya.NewAuthPacketConn(packet).WithSocks5Prefix(true).WithRealTarget(shared.LocalAddr())
	_, _ = raw.WriteTo([]byte("unauthenticated"), target)
	select {
	case got := <-received:
		t.Fatalf("shared UDP bypass: %s", got)
	case <-time.After(30 * time.Millisecond):
	}
	pending := authSOCKS(t, lis.Addr().String(), "alice", "secret-alice")
	revoke()
	_ = pending.SetReadDeadline(time.Now().Add(time.Second))
	var pendingByte [1]byte
	if _, err := pending.Read(pendingByte[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("revoked pending command connection: %v", err)
	}
	_ = a.SetReadDeadline(time.Now().Add(time.Second))
	var byteBuf [1]byte
	if _, err = a.Read(byteBuf[:]); err == nil {
		t.Fatal("revoked association stayed open")
	}
	send(relayB, "bob")

	// Our outbound client must honor the returned association port too.
	endpoint, _ := netapi.ParseSysAddr(lis.Addr())
	parent, err := fixed.NewClient(fixed.Config{Host: endpoint.Hostname(), Port: int32(endpoint.Port())}, nil)
	if err != nil {
		t.Fatal(err)
	}
	outbound, err := NewClient(Config{User: "bob", Password: "secret-bob", Hostname: endpoint.Hostname()}, transparentProxy{parent})
	if err != nil {
		t.Fatal(err)
	}
	defer outbound.Close()
	native, err := outbound.PacketConn(t.Context(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer native.Close()
	_ = native.SetDeadline(time.Now().Add(time.Second))
	if _, err = native.WriteTo([]byte("native"), target); err != nil {
		t.Fatal(err)
	}
	nativeReply := make([]byte, 256)
	n, _, err := native.ReadFrom(nativeReply)
	if err != nil || string(nativeReply[:n]) != "native" {
		t.Fatalf("native UDP relay: %q %v", nativeReply[:n], err)
	}
	if got := <-received; got != "bob" {
		t.Fatalf("native identity=%s", got)
	}
	// The independently configured legacy password remains accepted.
	old := authSOCKS(t, lis.Addr().String(), "old", "password")
	send(associate(t, old), "legacy")
}

func TestUserSOCKSDoesNotNegotiateAnonymous(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	s := &Server{authenticate: func(context.Context, string, []byte) (*proxyauth.Identity, error) {
		return nil, proxyauth.ErrUnauthorized
	}}
	result := make(chan error, 1)
	go func() { defer server.Close(); _, err := s.authenticateClient(server, make([]byte, 256)); result <- err }()
	_, _ = client.Write([]byte{5, 1, 0})
	var response [2]byte
	_, err := io.ReadFull(client, response[:])
	if err != nil || response != [2]byte{5, 255} {
		t.Fatalf("anonymous negotiation %v: %v", response, err)
	}
	if err := <-result; err == nil {
		t.Fatal("anonymous accepted")
	}
}

type transparentProxy struct{ netapi.Proxy }
