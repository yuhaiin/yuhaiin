package inbound

import (
	"errors"
	"path/filepath"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func TestSyncValidatesTrafficControlBeforeOpeningListeners(t *testing.T) {
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := plainstore.NewInboundStore(db.DB())
	if _, err := store.TrafficControl(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().ExecContext(t.Context(), `INSERT INTO inbound_traffic_control(id,config_json) VALUES(1,'{"enabled":true,"defaultProfile":"missing"}')`); err != nil {
		t.Fatal(err)
	}
	cfg := contract.Inbound{ID: "startup", Name: "startup", Enabled: true,
		Network:  contract.NewTypedNetwork(contract.TCPUDPNetwork{Host: "127.0.0.1:0", UDP: contract.UDPTCPOnly}),
		Protocol: contract.NewTypedProtocol(contract.MixedProtocol{}),
	}
	if err := store.Save(t.Context(), cfg, 1); err != nil {
		t.Fatal(err)
	}
	runtime := NewInbound(netapi.NewErrProxy(errors.New("unexpected outbound request")))
	t.Cleanup(func() { _ = runtime.Close() })
	if err := NewContractStore(store, runtime).Sync(t.Context()); err == nil {
		t.Fatal("invalid stored QoS was accepted")
	}
	for range runtime.store.Range {
		t.Fatal("listener opened before stored QoS was validated")
	}
}
