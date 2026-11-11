package inbound

import (
	"encoding/base64"
	"net/netip"
	"path/filepath"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/contract/transport"
	"github.com/Asutorufa/yuhaiin/pkg/net/peerrendezvous"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func TestPeerDiscoveryBlockPersistsAndAppliesWithoutRebind(t *testing.T) {
	ctx := t.Context()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := plainstore.NewInboundStore(db.DB())
	if err := store.SaveSettings(ctx, plainstore.InboundSettings{}); err != nil {
		t.Fatal(err)
	}
	runtime := NewInbound(direct.Default)
	t.Cleanup(func() { _ = runtime.Close() })
	contracts := NewContractStore(store, runtime)

	key := [32]byte{24}
	config := contract.Inbound{ID: "peer-discovery", Name: "Peer Discovery", Enabled: true,
		Network:  contract.NewTypedNetwork(contract.TCPUDPNetwork{Host: "127.0.0.1:0", UDP: contract.UDPUdpOnly}),
		Protocol: contract.NewTypedProtocol(contract.PeerDiscoveryProtocol{Tokens: []string{base64.StdEncoding.EncodeToString(key[:])}}),
	}
	if err := contracts.Save(ctx, config, 0); err != nil {
		t.Fatal(err)
	}
	pair := transport.PeerPairIDString(key)
	act := func(controller *ContractStore, action string) {
		t.Helper()
		if err := controller.UpdatePeerDiscoveryPair(ctx, contract.PeerDiscoveryAction{ID: config.ID, PairID: pair, Action: action}); err != nil {
			t.Fatal(err)
		}
	}
	check := func(controller *ContractStore, denial string) {
		t.Helper()
		list, err := controller.PeerDiscoveryPairs(ctx, config.ID)
		if err != nil || !list.Running || len(list.Items) != 1 || list.Items[0].ID != pair || list.Items[0].Blocked != (denial == "blocked") {
			t.Fatalf("pair list: %+v, %v", list, err)
		}
		server := controller.discoveryServer(config.ID)
		result, err := peerrendezvous.Lookup(ctx, netip.MustParseAddrPort(server.listen), key)
		if err != nil || result.Denial != denial || result.Endpoint.IsValid() {
			t.Fatalf("lookup: %+v, %v", result, err)
		}
	}
	server := contracts.discoveryServer(config.ID)
	act(contracts, "kick")
	check(contracts, "kicked")
	act(contracts, "block")
	check(contracts, "blocked")
	// Save the pre-block draft to simulate an editor that was already open.
	if err := contracts.Save(ctx, config, 0); err != nil {
		t.Fatal(err)
	}
	if contracts.discoveryServer(config.ID) != server {
		t.Fatal("updating the blacklist rebound the discovery socket")
	}
	check(contracts, "blocked")
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	restarted := NewInbound(direct.Default)
	t.Cleanup(func() { _ = restarted.Close() })
	controller := NewContractStore(store, restarted)
	if err := controller.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	check(controller, "blocked")
	act(controller, "unblock")
	check(controller, "")
}
