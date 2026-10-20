package store

import (
	"path/filepath"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestTrafficControlPersistenceAndValidation(t *testing.T) {
	ctx := t.Context()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := NewInboundStore(db.DB())
	empty, err := s.TrafficControl(ctx)
	if err != nil || empty.Enabled {
		t.Fatalf("unexpected defaults: %+v %v", empty, err)
	}
	cfg := trafficcontrol.Config{
		Enabled:         true,
		Global:          trafficcontrol.Profile{Upload: trafficcontrol.Rate{BytesPerSecond: 10000}},
		Profiles:        map[string]trafficcontrol.Profile{"bulk": {Download: trafficcontrol.Rate{BytesPerSecond: 20000, BurstBytes: 2000}}},
		InboundProfiles: map[string]string{"socks": "bulk"},
		RouteProfiles:   map[string]string{"route-1": "bulk"},
	}
	if err := s.SaveTrafficControl(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	got, err := s.TrafficControl(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Global.Upload.BytesPerSecond != 10000 || got.Profiles["bulk"].Download.BytesPerSecond != 20000 || got.RouteProfiles["route-1"] != "bulk" {
		t.Fatalf("round-trip failed: %+v", got)
	}
	bad := cfg
	bad.InboundProfiles = map[string]string{"wrong": "absent"}
	if err := s.SaveTrafficControl(ctx, bad); err == nil {
		t.Fatal("invalid profile was persisted")
	}
	got, err = s.TrafficControl(ctx)
	if err != nil || got.InboundProfiles["socks"] != "bulk" {
		t.Fatalf("invalid configuration replaced valid saved profile: %+v %v", got, err)
	}
}
