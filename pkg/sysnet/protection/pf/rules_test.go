package pf

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/policy"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
)

func basePolicy() protection.Policy {
	return protection.Policy{Mode: sysnet.ProtectionModeStandard, PrivateNetworks: policy.PrivateNetworks(),
		BypassNetworks: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8:1::/48"), netip.MustParsePrefix("198.51.100.7/32")}}
}

func lines(text string) []string {
	var out []string
	for l := range strings.SplitSeq(strings.TrimSpace(text), "\n") {
		if !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func TestCompileBaseline(t *testing.T) {
	rs, err := Compile(basePolicy(), Env{})
	if err != nil {
		t.Fatal(err)
	}
	got := lines(rs.Text)
	want := []string{
		"table <yuhaiin_private> const { 10.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12, 192.168.0.0/16, fc00::/7, 127.0.0.0/8, 169.254.0.0/16, ::1, fe80::/10 }",
		"table <yuhaiin_bypass> const { 198.51.100.7, 203.0.113.0/24, 2001:db8:1::/48 }",
		`pass out on lo0 all flags any keep state tag io.github.yuhaiin.pass label "yuhaiin-loopback"`,
		`pass out to <yuhaiin_private> flags any keep state tag io.github.yuhaiin.pass label "yuhaiin-private"`,
		`pass out inet to { 224.0.0.0/24, 255.255.255.255 } tag io.github.yuhaiin.pass label "yuhaiin-link-multicast"`,
		`pass out inet6 to ff02::/16 tag io.github.yuhaiin.pass label "yuhaiin-link-multicast6"`,
		`pass out inet proto udp from any port 68 to any port 67 tag io.github.yuhaiin.pass label "yuhaiin-dhcp"`,
		`pass out inet6 proto udp from any port 546 to any port 547 tag io.github.yuhaiin.pass label "yuhaiin-dhcp6"`,
		`pass out inet6 proto icmp6 all icmp6-type { routersol, neighbrsol, neighbradv } tag io.github.yuhaiin.pass label "yuhaiin-nd"`,
		`pass out to <yuhaiin_bypass> flags any keep state tag io.github.yuhaiin.pass label "yuhaiin-bypass"`,
		`block return out quick all ! tagged io.github.yuhaiin.pass label "yuhaiin-block-` + rs.ID + `"`,
	}
	// The private table keeps policy order after normalization (sorted by address).
	if got[0] == want[0] {
		t.Log("private table in definition order")
	}
	if !strings.HasPrefix(got[0], "table <yuhaiin_private> const {") {
		t.Fatalf("private table = %s", got[0])
	}
	if !slices.Equal(got[1:], want[1:]) {
		t.Fatalf("rules:\n%s\nwant:\n%s", strings.Join(got[1:], "\n"), strings.Join(want[1:], "\n"))
	}
	if rs.Rules != len(want)-2 {
		t.Fatalf("rule count %d", rs.Rules)
	}
	// Only the final block is quick: allowed traffic still reaches the
	// rules of other programs.
	for _, l := range got {
		if strings.Contains(l, "quick") && !strings.HasPrefix(l, "block") {
			t.Fatalf("pass rule uses quick: %s", l)
		}
	}
	if strings.Contains(rs.Text, "utun") || strings.Contains(rs.Text, "group") {
		t.Fatal("baseline allows tunnels or own traffic")
	}
}

func TestCompileRuntime(t *testing.T) {
	p := basePolicy()
	p.Tunnels = []protection.Tunnel{{Name: "utun7", IPv4: true}, {Name: "utun3", IPv4: true, IPv6: true}}
	p.OwnTraffic = true
	rs, err := Compile(p, Env{OwnGroup: 345})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`pass out on utun3 all flags any keep state (if-bound) tag io.github.yuhaiin.pass label "yuhaiin-tunnel"`,
		`pass out on utun7 all flags any keep state (if-bound) tag io.github.yuhaiin.pass label "yuhaiin-tunnel"`,
		`pass out proto tcp all group 345 flags any keep state tag io.github.yuhaiin.pass label "yuhaiin-own-tcp"`,
		`pass out proto udp all group 345 keep state tag io.github.yuhaiin.pass label "yuhaiin-own-udp"`,
	} {
		if !strings.Contains(rs.Text, want+"\n") {
			t.Fatalf("missing %q in\n%s", want, rs.Text)
		}
	}
	if !strings.HasSuffix(strings.TrimSpace(rs.Text), `label "yuhaiin-block-`+rs.ID+`"`) {
		t.Fatal("block rule is not last")
	}
	// Without a socket group, own traffic cannot be identified and is not allowed.
	rs2, _ := Compile(p, Env{})
	if strings.Contains(rs2.Text, "group") || rs2.ID == rs.ID {
		t.Fatalf("own traffic without group: %s", rs2.Text)
	}
	base, _ := Compile(basePolicy(), Env{OwnGroup: 345})
	if base.ID == rs.ID {
		t.Fatal("policy id does not follow the runtime part")
	}
}

func TestCompileEmptyBypassAndOrderIndependence(t *testing.T) {
	p := basePolicy()
	p.BypassNetworks = nil
	rs, err := Compile(p, Env{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rs.Text, "yuhaiin_bypass") {
		t.Fatal("empty bypass table rendered")
	}
	a, b := basePolicy(), basePolicy()
	slices.Reverse(b.BypassNetworks)
	slices.Reverse(b.PrivateNetworks)
	ra, _ := Compile(a, Env{})
	rb, _ := Compile(b, Env{})
	if ra.Text != rb.Text {
		t.Fatal("order of inputs changes the ruleset")
	}
}

func TestCompileRejectsUnsafeInput(t *testing.T) {
	for name, mutate := range map[string]func(*protection.Policy){
		"injection":  func(p *protection.Policy) { p.Tunnels = []protection.Tunnel{{Name: "utun0 all"}} },
		"quote":      func(p *protection.Policy) { p.Tunnels = []protection.Tunnel{{Name: `utun0"`}} },
		"newline":    func(p *protection.Policy) { p.Tunnels = []protection.Tunnel{{Name: "utun0\npass"}} },
		"no unit":    func(p *protection.Policy) { p.Tunnels = []protection.Tunnel{{Name: "utun"}} },
		"loopback":   func(p *protection.Policy) { p.Tunnels = []protection.Tunnel{{Name: "lo0"}} },
		"duplicate":  func(p *protection.Policy) { p.Tunnels = []protection.Tunnel{{Name: "utun1"}, {Name: "utun1"}} },
		"default":    func(p *protection.Policy) { p.BypassNetworks = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")} },
		"default v6": func(p *protection.Policy) { p.BypassNetworks = []netip.Prefix{netip.MustParsePrefix("::/0")} },
		"host bits":  func(p *protection.Policy) { p.BypassNetworks = []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")} },
		"mapped": func(p *protection.Policy) {
			p.BypassNetworks = []netip.Prefix{netip.MustParsePrefix("::ffff:192.0.2.0/120")}
		},
		"invalid":      func(p *protection.Policy) { p.PrivateNetworks = []netip.Prefix{{}} },
		"mode":         func(p *protection.Policy) { p.Mode = "strict" },
		"no mode":      func(p *protection.Policy) { p.Mode = "" },
		"many tunnels": func(p *protection.Policy) { p.Tunnels = make([]protection.Tunnel, protection.MaxTunnels+1) },
	} {
		p := basePolicy()
		mutate(&p)
		if _, err := Compile(p, Env{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Compile(basePolicy(), Env{OwnGroup: -1}); err == nil {
		t.Error("negative group accepted")
	}
}

const verboseRules = `No ALTQ support in kernel
ALTQ related functions disabled
pass out on lo0 all flags S/SA keep state tag io.github.yuhaiin.pass label "yuhaiin-loopback"
  [ Evaluations: 120       Packets: 64        Bytes: 5120        States: 3     ]
  [ Inserted: uid 0 pid 812 State Creations: 3     ]
pass out proto tcp all group 345 flags any keep state tag io.github.yuhaiin.pass label "yuhaiin-own-tcp"
  [ Evaluations: 40        Packets: 900       Bytes: 70000       States: 5     ]
pass out proto udp all group 345 keep state tag io.github.yuhaiin.pass label "yuhaiin-own-udp"
  [ Evaluations: 10        Packets: 20        Bytes: 2000        States: 2     ]
pass out on utun4 all flags S/SA keep state (if-bound) tag io.github.yuhaiin.pass label "yuhaiin-tunnel"
  [ Evaluations: 10        Packets: 20        Bytes: 2000        States: 2     ]
block return out quick all ! tagged io.github.yuhaiin.pass label "yuhaiin-block-0123456789abcdef"
  [ Evaluations: 77        Packets: 12        Bytes: 840         States: 0     ]
`

func TestParseRules(t *testing.T) {
	rules := ParseRules(verboseRules)
	if len(rules) != 5 {
		t.Fatalf("rules = %+v", rules)
	}
	if LoadedID(rules) != "0123456789abcdef" {
		t.Fatalf("id = %q", LoadedID(rules))
	}
	s := Summarize(rules)
	if !s.HasBlock || s.Blocked.Packets != 12 || s.Blocked.Bytes != 840 || s.OwnStates != 7 || !s.HasOwnStates || s.TunnelRules != 1 {
		t.Fatalf("summary = %+v", s)
	}
	if got := ParseRules("No ALTQ support in kernel\nALTQ related functions disabled\n"); len(got) != 0 {
		t.Fatalf("warnings parsed as rules: %+v", got)
	}
	if LoadedID(ParseRules(`pass out all label "other"`)) != "" {
		t.Fatal("foreign rules reported as Yuhaiin's")
	}
}

func TestParseInfoTokensAndReferences(t *testing.T) {
	if on, ok := ParseEnabled("No ALTQ support in kernel\nStatus: Enabled for 0 days 00:01:02           Debug: Urgent\n"); !on || !ok {
		t.Fatal("enabled not parsed")
	}
	if on, ok := ParseEnabled("Status: Disabled                              Debug: Urgent\n"); on || !ok {
		t.Fatal("disabled not parsed")
	}
	if _, ok := ParseEnabled("garbage"); ok {
		t.Fatal("unknown output parsed")
	}
	if ParseToken("No ALTQ support in kernel\npf enabled\nToken : 3954129321523498049\n") != "3954129321523498049" {
		t.Fatal("token")
	}
	if ParseToken("pf already enabled\n") != "" {
		t.Fatal("token without token")
	}
	refs := ParseReferences("TOKENS:\nPID      Process Name                TOKEN                 TIMESTAMP\n301      pfctl                       18446742974219694593  0 days 00:00:12\n77 x 3954129321523498049 1 days\n")
	if !slices.Equal(refs, []string{"18446742974219694593", "3954129321523498049"}) {
		t.Fatalf("refs = %v", refs)
	}
	main := "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"io.github.yuhaiin/*\" all\nanchor \"com.apple/*\" all\n"
	if !MainReferences(main, "anchor") || MainReferences("anchor \"com.apple/*\" all\n", "anchor") {
		t.Fatal("main references")
	}
	if MainReferences("anchor \"io.github.yuhaiin.evil/*\" all\n", "anchor") {
		t.Fatal("prefix match")
	}
}

func TestValidInterface(t *testing.T) {
	for _, ok := range []string{"utun0", "utun12", "en0", "bridge100"} {
		if ValidInterface(ok) != nil {
			t.Errorf("%s rejected", ok)
		}
	}
	for _, bad := range []string{"", "utun", "UTUN0", "utun0;", "en0 all", "a1234567890123"} {
		if ValidInterface(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
