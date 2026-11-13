package store

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestSystemNetworkStoreRoundTripAndRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	store := NewSystemNetworkStore(db.DB())
	empty, err := store.LoadSystemNetwork(ctx)
	if err != nil || empty.Routes == nil || len(empty.Routes) != 0 || empty.Forwarding.Rules == nil {
		t.Fatalf("empty config = %+v, %v", empty, err)
	}
	config := sysnet.Config{Routes: []sysnet.RouteRule{{ID: "a", Name: "Global", Enabled: true, Priority: 100,
		Match:  sysnet.RouteMatch{Mode: sysnet.ModeGlobal},
		Target: sysnet.RouteTarget{Type: sysnet.TargetTunInbound, InboundID: "tun"}}},
		Forwarding: sysnet.Forwarding{IPv4: true, Rules: []sysnet.ForwardRule{{ID: "f", Enabled: true, IngressInterface: "eth0",
			SourceCIDRs: []string{"192.168.20.0/24"}, Egress: sysnet.RouteTarget{Type: sysnet.TargetTunInbound, InboundID: "tun"}}}},
		Migrations: []sysnet.Migration{{InboundID: "tun", Source: "tun_routing:global", RuleID: "a"}}}
	if err := store.SaveSystemNetwork(ctx, config); err != nil {
		t.Fatal(err)
	}
	invalid := config
	invalid.Routes = []sysnet.RouteRule{{ID: "b", Match: sysnet.RouteMatch{Mode: "nope"}}}
	if err := store.SaveSystemNetwork(ctx, invalid); err == nil {
		t.Fatal("invalid configuration saved")
	}
	_ = db.Close()
	db, err = sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	got, err := NewSystemNetworkStore(db.DB()).LoadSystemNetwork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Routes) != 1 || got.Routes[0].Target.InboundID != "tun" || !got.Forwarding.IPv4 || got.Forwarding.Rules[0].SourceCIDRs[0] != "192.168.20.0/24" || got.Migrations[0].RuleID != "a" {
		t.Fatalf("restored config = %+v", got)
	}
}
