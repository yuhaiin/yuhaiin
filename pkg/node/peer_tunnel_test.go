package node

import (
	"context"
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/contract/transport"
	"github.com/Asutorufa/yuhaiin/pkg/net/peerrendezvous"
)

func TestPeerTunnelListFindsIdlePublisher(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
	defer cancel()
	listen := func() *net.UDPConn {
		t.Helper()
		pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		return pc
	}
	key := [32]byte{9}
	server := listen()
	coordinator := server.LocalAddr().(*net.UDPAddr).AddrPort()
	discovery := peerrendezvous.Serve(server, [][32]byte{key})
	t.Cleanup(func() { _ = discovery.Close() })
	routes := []string{"192.168.1.0/24"}
	invitation, err := (transport.LANLinkInvitation{
		Coordinator: coordinator.String(), Registration: base64.StdEncoding.EncodeToString(key[:]),
		Token: transport.NewLANLinkToken(), Routes: routes,
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	link := transport.LANLink{Invitation: invitation}
	runtime := newTestRuntime(t)
	for _, id := range []string{"enabled", "disabled"} {
		value := contract.Node{ID: id, Name: id, Enabled: id == "enabled", Chain: []contract.Protocol{{Type: transport.LANLinkType, LANLink: &link}}}
		if _, err := runtime.Save(ctx, value); err != nil {
			t.Fatal(err)
		}
	}
	list := func() contract.PeerTunnelPeer {
		t.Helper()
		got, err := runtime.PeerTunnelPeers(ctx, 99)
		if err != nil || len(got.Items) != 1 || got.Page.Total != 1 || got.Page.Page != 1 {
			t.Fatalf("peer list: %+v, %v", got, err)
		}
		peer := got.Items[0]
		if peer.NodeID != "enabled" || len(peer.Routes) != 1 || peer.Routes[0] != routes[0] {
			t.Fatalf("unexpected peer metadata: %+v", peer)
		}
		return peer
	}
	if peer := list(); peer.State != "offline" || peer.Endpoint != "" {
		t.Fatalf("unregistered publisher: %+v", peer)
	}
	publisher := peerrendezvous.NewSocket(listen(), coordinator, key, peerrendezvous.Publisher, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = publisher.ReadFrom(make([]byte, 2048))
	}()
	t.Cleanup(func() { _ = publisher.Close(); <-done })
	for {
		if peer := list(); peer.State == "online" {
			if peer.Endpoint != publisher.LocalAddr().String() {
				t.Fatalf("incorrect advertised endpoint: %+v", peer)
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	chained := contract.Node{ID: "chained", Name: "chained", Origin: "manual", Enabled: true, Chain: []contract.Protocol{
		{Type: transport.LANLinkType, LANLink: &link}, {Type: transport.LANLinkType, LANLink: &link},
	}}
	if err := chained.Validate(); err == nil || !strings.Contains(err.Error(), "first step") {
		t.Fatalf("LAN Link accepted after another chain step: %v", err)
	}
	active, err := runtime.Active(ctx)
	if err != nil || len(active) != 0 {
		t.Fatalf("lookup started a data-plane node: %+v, %v", active, err)
	}
}
