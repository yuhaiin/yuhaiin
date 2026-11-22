package nft

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/policy"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
)

func testPolicy() protection.Policy {
	return protection.Policy{Mode: sysnet.ProtectionModeStandard, PrivateNetworks: policy.PrivateNetworks(),
		BypassNetworks: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/25"), netip.MustParsePrefix("203.0.113.128/25"), netip.MustParsePrefix("2001:db8:1::/48")}}
}

func TestCompileTable(t *testing.T) {
	p := testPolicy()
	p.Tunnels = []protection.Tunnel{{Name: "tun0", IPv4: true}}
	p.OwnTraffic = true
	plan, err := Compile(p, Env{Tunnels: []Tunnel{{Name: "tun0", Index: 7}}, OwnMark: 0x500})
	if err != nil {
		t.Fatal(err)
	}
	text := plan.Text()
	for _, want := range []string{
		`oifname "lo" counter accept comment "yuhaiin-loopback"`,
		`ip daddr @private4 counter accept comment "yuhaiin-private"`,
		`ip6 daddr @private6 counter accept comment "yuhaiin-private"`,
		`ip daddr 224.0.0.0/24 counter accept`,
		`udp sport 68 udp dport 67 counter accept comment "yuhaiin-dhcp"`,
		`icmpv6 type 135 counter accept comment "yuhaiin-nd"`,
		`ip daddr @bypass4 counter accept comment "yuhaiin-bypass"`,
		`oif 7 counter accept comment "yuhaiin-tunnel"`,
		`meta mark 0x500 counter accept comment "yuhaiin-own"`,
		`meta l4proto tcp counter reject with tcp reset comment "yuhaiin-block-` + plan.ID + `"`,
		`meta l4proto != tcp counter reject with icmpx admin-prohibited`,
		"type filter hook output priority filter; policy accept;",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
	// Adjacent bypass prefixes merge into one interval (the kernel rejects
	// touching intervals).
	for _, s := range plan.Sets {
		if s.Name == "bypass4" && (len(s.Ranges) != 1 || s.Ranges[0].String() != "203.0.113.0-203.0.113.255") {
			t.Fatalf("bypass4 = %v", s.Ranges)
		}
	}
	// The reject rules are last; only they reject.
	last := plan.Rules[len(plan.Rules)-2:]
	for _, r := range plan.Rules[:len(plan.Rules)-2] {
		if r.Verdict != "accept" {
			t.Fatalf("non-final rule %v", r)
		}
	}
	if last[0].Verdict != "reject" || last[1].Verdict != "reject" || LoadedID([]string{last[0].Label}) != plan.ID {
		t.Fatalf("block rules = %v", last)
	}
}

func TestCompileWithoutRuntime(t *testing.T) {
	plan, err := Compile(testPolicy(), Env{OwnMark: 0x500})
	if err != nil {
		t.Fatal(err)
	}
	text := plan.Text()
	if strings.Contains(text, "oif ") || strings.Contains(text, "mark") {
		t.Fatalf("baseline allows a TUN or Yuhaiin's sockets:\n%s", text)
	}
	other, _ := Compile(testPolicy(), Env{Tunnels: []Tunnel{{Name: "tun0", Index: 9}}})
	if other.ID == plan.ID {
		t.Fatal("id does not follow the tunnel index")
	}
}

func TestCompileRejects(t *testing.T) {
	if _, err := Compile(testPolicy(), Env{Tunnels: []Tunnel{{Name: "tun0"}}}); err == nil {
		t.Fatal("tunnel without index accepted")
	}
	if _, err := Compile(testPolicy(), Env{Tunnels: []Tunnel{{Name: "lo", Index: 1}}}); err == nil {
		t.Fatal("loopback as tunnel accepted")
	}
	bad := testPolicy()
	bad.BypassNetworks = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	if _, err := Compile(bad, Env{}); err == nil {
		t.Fatal("default route bypass accepted")
	}
}

func TestCategoryAndRange(t *testing.T) {
	for label, want := range map[string]string{"yuhaiin-loopback": sysnet.RuleLoopback, "yuhaiin-own": sysnet.RuleOwn, "yuhaiin-tunnel": sysnet.RuleTunnel,
		"yuhaiin-block-x": sysnet.RuleBlock, "yuhaiin-nd": sysnet.RuleLocal, "foreign": sysnet.RuleOther} {
		if Category(label) != want {
			t.Errorf("%s -> %s", label, Category(label))
		}
	}
	if s := rangeString([]byte{10, 0, 0, 0}, []byte{11, 0, 0, 0}); s != "10.0.0.0/8" {
		t.Fatal(s)
	}
	if s := rangeString([]byte{10, 0, 0, 1}, []byte{10, 0, 0, 3}); s != "10.0.0.1-10.0.0.2" {
		t.Fatal(s)
	}
}
