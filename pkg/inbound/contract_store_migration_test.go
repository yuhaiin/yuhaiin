package inbound

import (
	"errors"
	"path/filepath"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	contractsysnet "github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/iface"
)

func TestContractStoreMigratesLegacyTunRouting(t *testing.T) {
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
	legacy := contract.Inbound{ID: "tun", Name: "tun", Enabled: false, Network: contract.NewTypedNetwork(contract.EmptyNetwork{}),
		Protocol: contract.NewTypedProtocol(contract.TunProtocol{Name: "tun://utun8", Routing: contract.TunRouting{Mode: "custom", GeoIPCountries: []string{"JP"}}})}
	if err := store.Save(ctx, legacy, 1); err != nil {
		t.Fatal(err)
	}
	manager := sysnet.New(sysnet.Options{Capabilities: sysnet.PlatformCapabilities("linux", true, false), Interfaces: func() ([]iface.Info, error) { return nil, nil }})
	t.Cleanup(func() { _ = manager.Close() })
	sysnetStore := plainstore.NewSystemNetworkStore(db.DB())
	if err := manager.SetStore(ctx, sysnetStore); err != nil {
		t.Fatal(err)
	}
	runtime := NewInbound(netapi.NewErrProxy(errors.New("test proxy")), WithSystemNetwork(manager))
	t.Cleanup(func() { _ = runtime.Close() })
	contracts := NewContractStore(store, runtime)
	contracts.SetLegacyTunMigration(manager)
	if err := contracts.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	stored, err := store.Get(ctx, "tun")
	if err != nil {
		t.Fatal(err)
	}
	if sysnet.HasLegacyRouting(stored) {
		t.Fatalf("legacy routing not cleared: %+v", stored.Protocol.Tun)
	}
	config, err := sysnetStore.LoadSystemNetwork(ctx)
	if err != nil || len(config.Routes) != 1 || config.Routes[0].Match.GeoIPCountries[0] != "JP" || config.Routes[0].Target.InboundID != "tun" {
		t.Fatalf("migrated config = %+v, %v", config, err)
	}

	// An API client (or restored backup) saving legacy fields again is
	// migrated on save without duplicating the identical rule.
	if err := contracts.Save(ctx, legacy, 2); err != nil {
		t.Fatal(err)
	}
	config, _ = sysnetStore.LoadSystemNetwork(ctx)
	if len(config.Routes) != 1 {
		t.Fatalf("duplicate rule after re-save: %+v", config.Routes)
	}
	if stored, _ = store.Get(ctx, "tun"); sysnet.HasLegacyRouting(stored) {
		t.Fatal("legacy routing stored after save")
	}
	if s := manager.Status(); len(s.Migrations) != 1 || s.Rules[0].State != contractsysnet.StateUnavailable {
		t.Fatalf("status = %+v", s)
	}
}
