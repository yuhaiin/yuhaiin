package inbound

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/contract/transport"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/node"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func TestLANLinkInvitationsAllocateAndConnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	state := filepath.Join(t.TempDir(), "state.db")
	db, err := sqlite.Open(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	runtime := NewInbound(direct.Default)
	t.Cleanup(func() { _ = runtime.Close() })
	store := NewContractStore(plainstore.NewInboundStore(db.DB()), runtime)
	authority := transport.NewLANLinkToken()
	discovery := contract.Inbound{
		ID: "discovery", Name: "Discovery", Enabled: true,
		Network:  contract.NewTypedNetwork(contract.TCPUDPNetwork{Host: "127.0.0.1:0", UDP: contract.UDPUdpOnly}),
		Protocol: contract.NewTypedProtocol(contract.PeerDiscoveryProtocol{RegistrationKeys: []string{authority}}),
	}
	if err := store.Save(ctx, discovery, 0); err != nil {
		t.Fatal(err)
	}
	routes := []string{"127.0.0.1/32"}
	// Exercise the exchange with an assignment that spans multiple UDP packets.
	for i := range 100 {
		routes = append(routes, fmt.Sprintf("192.168.%d.0/24", i))
	}
	gateway := contract.Inbound{
		ID: "gateway", Name: "Gateway", Enabled: true,
		Network: contract.NewTypedNetwork(contract.EmptyNetwork{}),
		Protocol: contract.NewTypedProtocol(contract.LANLinkPublisher{
			Coordinator: store.discoveryServer(discovery.ID).listen, Registration: authority, Routes: routes,
		}),
	}
	if err := store.Save(ctx, gateway, 0); err != nil {
		t.Fatal(err)
	}
	original, err := store.Get(ctx, gateway.ID)
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := netip.ParsePrefix(original.Protocol.LANLink.Subnet)
	if err != nil || !prefix.Addr().IsPrivate() {
		t.Fatalf("generated subnet = %v, %v", prefix, err)
	}
	nodes := node.NewNodeRuntime(state)
	t.Cleanup(func() { _ = nodes.Close() })

	invite := func(id string) (netapi.Proxy, contract.LANLinkInvitationResponse) {
		t.Helper()
		value, err := store.CreateLANLinkInvitation(ctx, gateway.ID)
		if err != nil {
			t.Fatal(err)
		}
		protocol, err := contractnode.NewTypedProtocol(transport.LANLink{Invitation: value.Invitation})
		if err != nil {
			t.Fatal(err)
		}
		draft := contractnode.Node{
			ID: id, Name: id, Origin: "manual", Enabled: true, Chain: []contractnode.Protocol{protocol},
		}
		saved, err := nodes.Save(ctx, draft)
		if err != nil {
			t.Fatal(err)
		}
		updated, err := nodes.Save(ctx, draft)
		if err != nil {
			t.Fatal(err)
		}
		key := saved.Chain[0].LANLink.PrivateKey
		if key == "" || key != updated.Chain[0].LANLink.PrivateKey {
			t.Fatal("saving the same invitation regenerated the client's private key")
		}
		proxy, err := nodes.GetDialerByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return proxy, value
	}
	var accepted atomic.Int32
	addr := tcpEcho(t, "127.0.0.1", &accepted)
	dial := func(proxy netapi.Proxy) net.Conn {
		t.Helper()
		c, err := proxy.Conn(ctx, addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	echo := func(c net.Conn) error {
		if err := c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			return err
		}
		if _, err := c.Write([]byte("link")); err != nil {
			return err
		}
		var data [4]byte
		_, err := io.ReadFull(c, data[:])
		if err == nil && string(data[:]) != "link" {
			t.Errorf("echo = %q", data)
		}
		return err
	}
	first, firstInvite := invite("first")
	target, matched := nodes.LANLinkTarget(ctx, netip.MustParseAddr("127.0.0.1"))
	if !matched || target.ID != "first" {
		t.Fatalf("invitation did not install a LAN route: %+v, %v", target, matched)
	}
	firstConn := dial(first)
	if err := echo(firstConn); err != nil {
		t.Fatal(err)
	}
	second, secondInvite := invite("second")
	if firstInvite.Address == secondInvite.Address || !prefix.Contains(netip.MustParseAddr(firstInvite.Address)) ||
		!prefix.Contains(netip.MustParseAddr(secondInvite.Address)) {
		t.Fatalf("invalid address allocations %s and %s in %s", firstInvite.Address, secondInvite.Address, prefix)
	}
	target, matched = nodes.LANLinkTarget(ctx, netip.MustParseAddr("127.0.0.1"))
	if !matched || target.ID != "" {
		t.Fatalf("overlapping LAN routes were not reported as ambiguous: %+v, %v", target, matched)
	}
	secondConn := dial(second)
	if err := echo(secondConn); err != nil {
		t.Fatal(err)
	}
	udp := udpEcho(t)
	datagram, err := second.PacketConn(ctx, udp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = datagram.Close() })
	if err := datagram.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := datagram.WriteTo([]byte("lan link"), udp); err != nil {
		t.Fatal(err)
	}
	var udpData [32]byte
	n, from, err := datagram.ReadFrom(udpData[:])
	if err != nil || from.String() != udp.String() || string(udpData[:n]) != "lan link" {
		t.Fatalf("UDP echo: %q from %v, %v", udpData[:n], from, err)
	}
	if err := echo(firstConn); err != nil {
		t.Fatalf("adding a client interrupted the existing tunnel: %v", err)
	}
	if err := store.RevokeLANLinkClient(ctx, contract.LANLinkClientRequest{ID: gateway.ID, ClientID: firstInvite.ClientID}); err != nil {
		t.Fatal(err)
	}
	if err := echo(firstConn); err == nil {
		t.Fatal("revoked client still forwards data")
	}
	if err := echo(secondConn); err != nil {
		t.Fatalf("revoking the first client interrupted the second: %v", err)
	}
	// An editor opened before either invitation cannot restore revoked clients
	// or lose the live client's address when changing the tunnel subnet.
	override := "172.20.7.0/24"
	if prefix.String() == override {
		override = "172.20.8.0/24"
	}
	original.Protocol.LANLink.Subnet = override
	if err := store.Save(ctx, original, 0); err != nil {
		t.Fatal(err)
	}
	current, err := store.Get(ctx, gateway.ID)
	if err != nil {
		t.Fatal(err)
	}
	currentLink := current.Protocol.LANLink
	if currentLink.Subnet != override || len(currentLink.Clients) != 1 || currentLink.Clients[0].ID != secondInvite.ClientID {
		t.Fatalf("subnet edit lost the live assignment: %+v", currentLink)
	}
	deadline := time.Now().Add(12 * time.Second)
	for {
		retry, cancel := context.WithTimeout(ctx, time.Second)
		conn, err := second.Conn(retry, addr)
		cancel()
		if err == nil {
			if err := echo(conn); err == nil {
				_ = conn.Close()
				break
			}
			_ = conn.Close()
		}
		if time.Now().After(deadline) {
			t.Fatal("client did not reconnect after changing the subnet")
		}
		time.Sleep(150 * time.Millisecond)
	}
}
