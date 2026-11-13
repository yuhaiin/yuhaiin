package forward

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func p(values ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, v := range values {
		out = append(out, netip.MustParsePrefix(v))
	}
	return out
}

func TestCompileSideRouter(t *testing.T) {
	plan := Plan{IPv4: true, IPv6: true, Rules: []Rule{
		{ID: "lan", Ingress: "eth0", Sources: p("192.168.20.0/24", "fd20::/64"), Egress: Egress{Name: "tun0", Link: 7}},
		{ID: "office", Ingress: "eth0", Sources: p("192.168.20.50/32"), Destinations: p("10.10.0.0/16"), Egress: Egress{Name: "eth1", Link: 3, Gateway: netip.MustParseAddr("10.77.31.1")}, Masquerade: true},
	}}
	c, err := Compile(plan)
	if err != nil {
		t.Fatal(err)
	}
	wantRules := []IPRule{
		{Priority: 29000, Table: 6300, Ingress: "eth0", Src: p("192.168.20.0/24")[0]},
		{Priority: 29000, Table: 6300, V6: true, Ingress: "eth0", Src: p("fd20::/64")[0]},
		{Priority: 29001, Table: 6301, Ingress: "eth0", Src: p("192.168.20.50/32")[0]},
	}
	if !slices.Equal(c.Rules, wantRules) {
		t.Fatalf("rules = %v", c.Rules)
	}
	wantRoutes := []TableRoute{
		{Table: 6300, Prefix: p("0.0.0.0/1")[0], Link: 7}, {Table: 6300, Prefix: p("128.0.0.0/1")[0], Link: 7},
		{Table: 6300, Prefix: p("::/1")[0], Link: 7}, {Table: 6300, Prefix: p("8000::/1")[0], Link: 7},
		{Table: 6301, Prefix: p("10.10.0.0/16")[0], Link: 3, Gateway: netip.MustParseAddr("10.77.31.1")},
	}
	if !slices.Equal(c.Routes, wantRoutes) {
		t.Fatalf("routes = %v", c.Routes)
	}
	// Only configured sources are forwarded from the ingress; NAT only where enabled.
	var accepts, drops, masq int
	for _, f := range c.Filter {
		switch f.Action {
		case "accept":
			accepts++
		case "drop":
			drops++
			if f.Ingress != "eth0" || f.Src.IsValid() {
				t.Fatalf("drop rule too broad: %+v", f)
			}
		case "masquerade":
			masq++
			if f.Egress != "eth1" || f.Src != p("192.168.20.50/32")[0] {
				t.Fatalf("masquerade = %+v", f)
			}
		}
	}
	if accepts != 3 || drops != 1 || masq != 1 {
		t.Fatalf("filter = %+v", c.Filter)
	}
	if c.Filter[len(c.Filter)-1].Action != "drop" {
		t.Fatal("drop must follow the accepts")
	}
}

func TestCompileFamiliesAndTProxy(t *testing.T) {
	rule := Rule{ID: "t", Ingress: "eth0", Sources: p("192.168.20.0/24", "fd20::/64"), Egress: Egress{TProxyPort: 7893}}
	c, err := Compile(Plan{IPv4: true, Rules: []Rule{rule}})
	if err != nil {
		t.Fatal(err)
	}
	// IPv6 forwarding is off: nothing for the IPv6 source.
	for _, f := range c.Filter {
		if f.Src.IsValid() && f.Src.Addr().Is6() {
			t.Fatalf("IPv6 rule without IPv6 forwarding: %+v", f)
		}
	}
	if !slices.Equal(c.Rules, []IPRule{{Priority: TProxyRulePriority, Table: TProxyTable, Ingress: "eth0", Mark: TProxyMark}}) {
		t.Fatalf("tproxy rules = %v", c.Rules)
	}
	if len(c.Routes) != 1 || !c.Routes[0].Local || c.Routes[0].Table != TProxyTable {
		t.Fatalf("tproxy routes = %v", c.Routes)
	}
	tproxy := 0
	for _, f := range c.Filter {
		if f.Action == "tproxy" {
			tproxy++
			if f.Port != 7893 || f.Chain != "prerouting" {
				t.Fatalf("tproxy rule = %+v", f)
			}
		}
	}
	if tproxy != 2 {
		t.Fatalf("want tcp and udp interception, got %d", tproxy)
	}
	// Forwarding off: no kernel state at all.
	c, _ = Compile(Plan{Rules: []Rule{rule}})
	if len(c.Rules)+len(c.Routes)+len(c.Filter) != 0 {
		t.Fatalf("state compiled with forwarding off: %+v", c)
	}
}

func writeSysctl(t *testing.T, root, key, value string) string {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSysctlOwnership(t *testing.T) {
	root := t.TempDir()
	v4 := writeSysctl(t, root, "net/ipv4/ip_forward", "0")
	v6 := writeSysctl(t, root, "net/ipv6/conf/all/forwarding", "1")
	s := &Sysctl{Root: root}
	if err := s.Set(SysctlIPv4, true); err != nil {
		t.Fatal(err)
	}
	if err := s.Set(SysctlIPv6, true); err != nil {
		t.Fatal(err)
	}
	if readFile(t, v4) != "1" || !s.Owned(SysctlIPv4) || s.Owned(SysctlIPv6) {
		t.Fatal("enable ownership")
	}
	// Disabling restores only what was changed here.
	if err := s.Set(SysctlIPv4, false); err != nil {
		t.Fatal(err)
	}
	if err := s.Set(SysctlIPv6, false); err != nil {
		t.Fatal(err)
	}
	if readFile(t, v4) != "0" || readFile(t, v6) != "1\n" {
		t.Fatalf("restore: v4=%q v6=%q", readFile(t, v4), readFile(t, v6))
	}
	// Another service turned it off meanwhile: not touched again.
	if err := s.Set(SysctlIPv4, true); err != nil {
		t.Fatal(err)
	}
	writeSysctl(t, root, "net/ipv4/ip_forward", "0")
	if err := s.Set(SysctlIPv4, false); err != nil {
		t.Fatal(err)
	}
	if readFile(t, v4) != "0\n" || s.Owned(SysctlIPv4) {
		t.Fatal("external change overwritten")
	}
}

func TestCompileRoutesEgressAndAllSources(t *testing.T) {
	c, err := Compile(Plan{IPv4: true, IPv6: true, Rules: []Rule{{ID: "all", Ingress: "eth0", Egress: Egress{Routes: true}}}})
	if err != nil {
		t.Fatal(err)
	}
	// Following the routing table needs no policy rule or table.
	if len(c.Rules) != 0 || len(c.Routes) != 0 {
		t.Fatalf("routes egress compiled policy routing: %+v", c)
	}
	accepts := 0
	for _, f := range c.Filter {
		if f.Action == "accept" {
			accepts++
			if f.Src.Bits() != 0 {
				t.Fatalf("no sources must mean every device: %+v", f)
			}
		}
	}
	if accepts != 2 {
		t.Fatalf("filter = %+v", c.Filter)
	}
}

func TestCompilePF(t *testing.T) {
	hop := func(link int, v6 bool) (netip.Addr, error) {
		if v6 {
			return netip.MustParseAddr("fdfe:a::1"), nil
		}
		return netip.MustParseAddr("172.19.0.1"), nil
	}
	plan := Plan{IPv4: true, IPv6: true, Rules: []Rule{
		{ID: "office", Ingress: "en1", Sources: p("192.168.20.50/32"), Destinations: p("10.10.0.0/16"), Egress: Egress{Name: "en0", Link: 4, Gateway: netip.MustParseAddr("192.168.1.1")}, Masquerade: true},
		{ID: "lan", Ingress: "en1", Sources: p("192.168.20.0/24", "fd20::/64"), Egress: Egress{Name: "utun8", Link: 9}},
		{ID: "rest", Ingress: "bridge0", Egress: Egress{Routes: true}},
	}}
	got, err := CompilePF(plan, hop)
	if err != nil {
		t.Fatal(err)
	}
	want := `nat on en0 inet from 192.168.20.50/32 to any -> (en0)
pass in quick on en1 inet from 192.168.20.50/32 to self keep state
pass in quick on en1 route-to (en0 192.168.1.1) inet from 192.168.20.50/32 to 10.10.0.0/16 keep state
pass in quick on en1 inet from 192.168.20.0/24 to self keep state
pass in quick on en1 route-to (utun8 172.19.0.1) inet from 192.168.20.0/24 to any keep state
pass in quick on en1 inet6 from fd20::/64 to self keep state
pass in quick on en1 route-to (utun8 fdfe:a::1) inet6 from fd20::/64 to any keep state
pass in quick on bridge0 inet from 0.0.0.0/0 to self keep state
pass in quick on bridge0 inet6 from ::/0 to self keep state
pass in quick on en1 inet from 192.168.20.50/32 keep state
pass in quick on en1 inet from 192.168.20.0/24 keep state
pass in quick on en1 inet6 from fd20::/64 keep state
pass in quick on bridge0 inet from 0.0.0.0/0 keep state
pass in quick on bridge0 inet6 from ::/0 keep state
pass in quick on en1 inet to { 224.0.0.0/4, 255.255.255.255 }
block in quick on en1 inet to ! self
pass in quick on en1 inet6 to { ff00::/8, fe80::/10 }
block in quick on en1 inet6 to ! self
pass in quick on bridge0 inet to { 224.0.0.0/4, 255.255.255.255 }
block in quick on bridge0 inet to ! self
pass in quick on bridge0 inet6 to { ff00::/8, fe80::/10 }
block in quick on bridge0 inet6 to ! self
`
	if got != want {
		t.Fatalf("pf rules:\n%s\nwant:\n%s", got, want)
	}
	if empty, _ := CompilePF(Plan{Rules: plan.Rules}, hop); empty != "" {
		t.Fatalf("rules compiled with forwarding off: %q", empty)
	}
	if _, err := CompilePF(Plan{IPv4: true, Rules: []Rule{{ID: "t", Ingress: "en1", Egress: Egress{TProxyPort: 1}}}}, hop); err == nil {
		t.Fatal("TProxy accepted on macOS")
	}
}

func TestLinkForwardingOwnership(t *testing.T) {
	state := map[linkFamily]bool{{2, false}: false, {3, false}: true, {2, true}: false}
	var sets []string
	l := &LinkForwarding{
		Get: func(link int, v6 bool) (bool, error) {
			on, ok := state[linkFamily{link, v6}]
			if !ok {
				return false, ErrLinkGone
			}
			return on, nil
		},
		Set: func(link int, v6, on bool) error {
			sets = append(sets, fmt.Sprintf("%d/%v=%v", link, v6, on))
			state[linkFamily{link, v6}] = on
			return nil
		},
	}
	if err := l.Apply(map[int]bool{2: true, 3: true}, true, true); err == nil {
		t.Fatal("missing IPv6 interface error was hidden")
	}
	if !state[linkFamily{2, false}] || !state[linkFamily{2, true}] {
		t.Fatal("forwarding not enabled")
	}
	// Interface 3 was already forwarding: never turned off by us.
	if err := l.Apply(nil, false, false); err != nil {
		t.Fatal(err)
	}
	if state[linkFamily{2, false}] || state[linkFamily{2, true}] || !state[linkFamily{3, false}] {
		t.Fatalf("restore = %v (sets %v)", state, sets)
	}
	// Turned off by someone else meanwhile: left alone.
	if err := l.Apply(map[int]bool{2: true}, true, false); err != nil {
		t.Fatal(err)
	}
	state[linkFamily{2, false}] = false
	sets = nil
	if err := l.Apply(nil, false, false); err != nil || len(sets) != 0 {
		t.Fatalf("changed a setting turned off elsewhere: %v %v", sets, err)
	}
}
