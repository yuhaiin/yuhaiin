package wfp

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/policy"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
)

func testPolicy() protection.Policy {
	return protection.Policy{Mode: sysnet.ProtectionModeStandard, StartAtBoot: true, PrivateNetworks: policy.PrivateNetworks(),
		BypassNetworks: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32")},
		Tunnels:        []protection.Tunnel{{Name: "Yuhaiin"}}, OwnTraffic: true}
}

func TestCompileFilters(t *testing.T) {
	plan, err := Compile(testPolicy(), Env{App: `C:\Program Files\yuhaiin\yuhaiin.exe`, Tunnels: []Tunnel{{Name: "Yuhaiin", LUID: 0x6000000001}}})
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	var blocks, runtime int
	for _, f := range plan.Filters {
		counts[Category(f.Label)]++
		if !f.Permit {
			blocks++
			if f.Weight >= weightPermit || len(f.Conditions) != 0 {
				t.Fatalf("block filter %+v", f)
			}
		}
		if f.Runtime {
			runtime++
			if f.Persistent || f.Weight != weightRuntime {
				t.Fatalf("runtime filter %+v", f)
			}
		} else if !f.Persistent {
			t.Fatalf("baseline filter not persistent with start at boot: %+v", f)
		}
	}
	// IPv4 and IPv6 each: block, loopback, TUN, Yuhaiin.
	if blocks != 2 || runtime != 4 || counts[sysnet.RuleLoopback] != 2 || counts[sysnet.RuleBypass] != 2 || counts[sysnet.RuleLocal] < 6 {
		t.Fatalf("counts %v blocks %d runtime %d", counts, blocks, runtime)
	}
	// Stable, distinct IDs.
	again, _ := Compile(testPolicy(), Env{App: `C:\Program Files\yuhaiin\yuhaiin.exe`, Tunnels: []Tunnel{{Name: "Yuhaiin", LUID: 0x6000000001}}})
	seen := map[[16]byte]bool{}
	for i, f := range plan.Filters {
		if f.GUID() != again.Filters[i].GUID() {
			t.Fatal("ids not stable")
		}
		if seen[f.GUID()] {
			t.Fatalf("duplicate id for %s", f.Key())
		}
		seen[f.GUID()] = true
	}
	if !strings.Contains(plan.Filters[0].String(), "permit outbound IPv4 loopback") {
		t.Fatal(plan.Filters[0].String())
	}
}

func TestCompileWithoutRuntimeAndBoot(t *testing.T) {
	p := testPolicy()
	p.StartAtBoot = false
	plan, err := Compile(p, Env{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range plan.Filters {
		if f.Runtime || f.Persistent {
			t.Fatalf("%+v", f)
		}
	}
	if _, err := Compile(p, Env{Tunnels: []Tunnel{{Name: "x"}}}); err == nil {
		t.Fatal("tunnel without LUID accepted")
	}
}

func TestManyBypassPrefixesAreChunked(t *testing.T) {
	p := testPolicy()
	p.BypassNetworks = nil
	for i := range 2500 {
		p.BypassNetworks = append(p.BypassNetworks, netip.PrefixFrom(netip.AddrFrom4([4]byte{11, byte(i >> 8), byte(i), 0}), 24))
	}
	plan, err := Compile(p, Env{})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range plan.Filters {
		if f.Label == "yuhaiin-bypass" {
			n++
			if len(f.Conditions) > maxPrefixesPerFilter {
				t.Fatal("filter too large")
			}
		}
	}
	if n != 3 {
		t.Fatalf("bypass filters = %d", n)
	}
}
