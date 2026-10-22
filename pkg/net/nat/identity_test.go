package nat

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

func TestAuthenticatedNATIsolatesIdentitiesAndPreservesFullCone(t *testing.T) {
	aliceCtx, revoke := context.WithCancel(t.Context())
	defer revoke()
	alice := &proxyauth.Identity{UserID: "alice", CredentialID: "alice-phone", Context: aliceCtx}
	bob := &proxyauth.Identity{UserID: "bob", CredentialID: "bob-phone", Context: t.Context()}
	var mu sync.Mutex
	var remotes []net.Conn
	dials := make(chan string, 8)
	table := NewTable(nil, lifecycleDialer{dial: func(ctx context.Context) (net.PacketConn, error) {
		identity := netapi.TrafficIdentity(ctx)
		dials <- identity.UserID
		local, remote := net.Pipe()
		mu.Lock()
		remotes = append(remotes, remote)
		mu.Unlock()
		return &lifecyclePacketConn{Conn: local, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{})}, nil
	}})
	defer func() {
		_ = table.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, remote := range remotes {
			_ = remote.Close()
		}
	}()
	write := func(identity *proxyauth.Identity, port uint16) error {
		base := lifecyclePacket()
		defer base.DecRef()
		packet := netapi.NewPacket(base.Src(), netapi.ParseIPAddr("udp", net.ParseIP("192.0.2.8"), port), pool.Clone([]byte("test")), base.ReplyWriter())
		defer packet.DecRef()
		packet.Identity = identity
		packet.MigrateID = 12345
		netapi.WithInboundID("entry")(packet)
		return table.Write(t.Context(), packet)
	}
	if err := write(alice, 80); err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-dials:
		if id != "alice" {
			t.Fatal(id)
		}
	case <-time.After(time.Second):
		t.Fatal("missing alice socket")
	}
	if err := write(alice, 443); err != nil {
		t.Fatal(err)
	}
	if err := write(bob, 80); err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-dials:
		if id != "bob" {
			t.Fatalf("destination split alice socket: %s", id)
		}
	case <-time.After(time.Second):
		t.Fatal("bob reused alice socket")
	}
	select {
	case id := <-dials:
		t.Fatalf("extra socket: %s", id)
	case <-time.After(20 * time.Millisecond):
	}
	source, ok := table.authenticatedSources.Load(authenticatedSourceKey{alice.CredentialID, "entry", 12345})
	if !ok {
		t.Fatal("missing authenticated source")
	}
	revoke()
	awaitClosed(t, source.done)
	if err := write(alice, 80); err == nil {
		t.Fatal("revoked identity admitted a packet")
	}
	if err := write(bob, 443); err != nil {
		t.Fatal(err)
	}
}
