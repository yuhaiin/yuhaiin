package trafficcontrol

import (
	"encoding/json"
	"testing"
)

func TestPolicyJSONAndDirection(t *testing.T) {
	src := Config{Enabled: true, Profiles: map[string]Profile{"bulk": {Download: Rate{BytesPerSecond: 80000, BurstBytes: 16000}}}, RouteProfiles: map[string]string{"route-1": "bulk"}}
	raw, err := json.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	var out Config
	if err = json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.RouteProfiles["route-1"] != "bulk" || out.Profiles["bulk"].Download.BurstBytes != 16000 {
		t.Fatalf("%s -> %+v", raw, out)
	}
}

func TestRouteBindingSuppressesDefaultProfile(t *testing.T) {
	m := NewManager()
	cfg := Config{
		Enabled:        true,
		DefaultProfile: "default",
		Profiles: map[string]Profile{
			"default": {Upload: Rate{BytesPerSecond: 1, BurstBytes: 1}},
			"route":   {Upload: Rate{BytesPerSecond: 1, BurstBytes: 10}},
		},
		RouteProfiles: map[string]string{"route-id": "route"},
	}
	if err := m.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	if !m.Resolve("", "route-id").AllowDatagram(Upload, 10) {
		t.Fatal("matching route incorrectly inherited the default profile")
	}
}

func TestPolicyUpdatesShareAggregateBudget(t *testing.T) {
	m := NewManager()
	existing := m.Resolve("client", "rule")
	cfg := Config{Enabled: true, Global: Profile{Upload: Rate{BytesPerSecond: 1, BurstBytes: 100}}}
	if err := m.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	if !existing.AllowDatagram(Upload, 100) {
		t.Fatal("existing policy did not observe enabled cap")
	}
	for range 3 {
		if err := m.Apply(cfg); err != nil {
			t.Fatal(err)
		}
		if m.Resolve("client", "rule").AllowDatagram(Upload, 100) {
			t.Fatal("identical save reset shared global burst")
		}
		if existing.AllowDatagram(Upload, 100) {
			t.Fatal("existing policy retained a separate global budget")
		}
	}
	cfg.Profiles = map[string]Profile{"unrelated": {}}
	if err := m.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	if existing.AllowDatagram(Upload, 100) {
		t.Fatal("unrelated profile edit reset global budget")
	}
	cfg.Global.Upload.BytesPerSecond = 2
	if err := m.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	if existing.AllowDatagram(Upload, 100) {
		t.Fatal("rate change granted a fresh burst")
	}
}

func TestPolicyRebindsExistingIdentity(t *testing.T) {
	m := NewManager()
	cfg := Config{Enabled: true, Profiles: map[string]Profile{"small": {Upload: Rate{BytesPerSecond: 1, BurstBytes: 1}}}}
	p := m.Resolve("client", "rule")
	if err := m.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	if !p.AllowDatagram(Upload, 2) {
		t.Fatal("unbound client limited")
	}
	cfg.InboundProfiles = map[string]string{"client": "small"}
	if err := m.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	if p.AllowDatagram(Upload, 2) {
		t.Fatal("existing stream did not observe new binding")
	}
	cfg.InboundProfiles = nil
	if err := m.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	if !p.AllowDatagram(Upload, 2) {
		t.Fatal("removed binding still limited stream")
	}
}
