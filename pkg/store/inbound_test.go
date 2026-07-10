package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestInboundStoreSaveGetListDelete(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	store := NewInboundStore(sqliteStore.DB())
	input := contract.Inbound{
		ID:      "reversehttp",
		Name:    "reversehttp",
		Enabled: true,
		Network: contract.NewTypedNetwork(contract.TCPUDPNetwork{Host: ":9002", UDP: contract.UDPTCPOnly}),
		Transports: []contract.Transport{
			contract.NewTypedTransport(contract.NormalTransport{}),
		},
		Protocol: contract.NewTypedProtocol(contract.ReverseHTTPProtocol{URL: "http://127.0.0.1:3000"}),
	}

	if err := store.Save(ctx, input, 123); err != nil {
		t.Fatal(err)
	}

	got, err := store.Get(ctx, "reversehttp")
	if err != nil {
		t.Fatal(err)
	}
	if got.Protocol.ReverseHTTP.URL != "http://127.0.0.1:3000" {
		t.Fatalf("got protocol = %+v", got.Protocol)
	}

	var networkType, protocolType, transportTypes string
	if err := sqliteStore.DB().QueryRowContext(ctx, `
		SELECT network_type, protocol_type, transport_types_json
		FROM inbounds_v2
		WHERE id = 'reversehttp'
	`).Scan(&networkType, &protocolType, &transportTypes); err != nil {
		t.Fatal(err)
	}
	if networkType != contract.NetworkTCPUDP || protocolType != contract.ProtocolReverseHTTP || transportTypes != `["normal"]` {
		t.Fatalf("projection = network:%q protocol:%q transports:%q", networkType, protocolType, transportTypes)
	}

	list, err := store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != "reversehttp" {
		t.Fatalf("list = %+v", list)
	}

	if err := store.Delete(ctx, "reversehttp"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, "reversehttp"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after delete error = %v", err)
	}
}

func TestInboundStoreRejectsInvalidTaggedObject(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	store := NewInboundStore(sqliteStore.DB())
	err = store.Save(ctx, contract.Inbound{
		ID:      "broken",
		Name:    "broken",
		Enabled: true,
		Network: contract.NewTypedNetwork(contract.EmptyNetwork{}),
		Protocol: contract.Protocol{
			Type:  contract.ProtocolReverseHTTP,
			Mixed: &contract.MixedProtocol{},
		},
	}, 0)
	if err == nil {
		t.Fatal("Save succeeded for mismatched protocol tagged object")
	}
}

func TestInboundStoreSettings(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	store := NewInboundStore(sqliteStore.DB())
	input := InboundSettings{HijackDNS: true, HijackDNSFakeIP: false, Sniff: true}
	if err := store.SaveSettings(ctx, input); err != nil {
		t.Fatal(err)
	}
	got, err := store.Settings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got != input {
		t.Fatalf("settings = %+v, want %+v", got, input)
	}
}
