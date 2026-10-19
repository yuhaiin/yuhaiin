package node

import (
	"encoding/json/v2"
	"testing"
)

func TestZeroTierTaggedJSONRoundTrip(t *testing.T) {
	config := ZeroTier{
		NetworkID: "8056c2e21c000001",
		Identity: "home",
		Listen: ":0",
		Moons: []ZeroTierMoon{{ID: "fffffffffffffffe", Seed: "0123456789abcdef"}},
	}
	protocol, err := NewTypedProtocol(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.Validate(); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(protocol)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Protocol
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
	if decoded.Type != "zerotier" || decoded.ZeroTier == nil {
		t.Fatalf("unexpected ZeroTier variant: %+v", decoded)
	}
	if decoded.ZeroTier.NetworkID != config.NetworkID || decoded.ZeroTier.Identity != config.Identity {
		t.Fatalf("controller network or persisted identity changed: %+v", decoded.ZeroTier)
	}
	if len(decoded.ZeroTier.Moons) != 1 || decoded.ZeroTier.Moons[0] != config.Moons[0] {
		t.Fatalf("moon identity lost precision during serialization: %+v", decoded.ZeroTier.Moons)
	}
}
