package forward

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

type fakePF struct {
	calls   []string
	sysctl  map[string]string
	anchors bool
	reject  bool
}

func (f *fakePF) run(stdin, name string, args ...string) (string, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	switch {
	case strings.HasSuffix(name, "sysctl") && args[0] == "-n":
		return f.sysctl[args[1]] + "\n", nil
	case strings.HasSuffix(name, "sysctl"):
		k, v, _ := strings.Cut(args[1], "=")
		f.sysctl[k] = v
		return "", nil
	case call == "/sbin/pfctl -s rules":
		if f.anchors {
			return "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n", nil
		}
		return "", nil
	case call == "/sbin/pfctl -s nat":
		if f.anchors {
			return "nat-anchor \"com.apple/*\" all\n", nil
		}
		return "", nil
	case strings.Contains(call, "-n -a"):
		if f.reject {
			return "", errors.New("syntax error")
		}
		return "", nil
	case call == "/sbin/pfctl -E":
		return "pf enabled\nToken : 1234567\n", nil
	}
	return "", nil
}

func newFake(anchors bool) (*Manager, *fakePF) {
	f := &fakePF{sysctl: map[string]string{darwinSysctlIPv4: "0", darwinSysctlIPv6: "0"}, anchors: anchors}
	m := New()
	m.run = f.run
	return m, f
}

func darwinPlan() Plan {
	return Plan{IPv4: true, Rules: []Rule{{ID: "lan", Ingress: "en1", Sources: []netip.Prefix{netip.MustParsePrefix("192.168.20.0/24")},
		Egress: Egress{Name: "en0", Link: 4, Gateway: netip.MustParseAddr("192.168.1.1")}, Masquerade: true}}}
}

func TestDarwinApplyAndClose(t *testing.T) {
	m, f := newFake(true)
	if err := m.Apply(darwinPlan()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(f.calls, "\n")
	for _, want := range []string{"/sbin/pfctl -n -a com.apple/yuhaiin -f -", "/sbin/pfctl -a com.apple/yuhaiin -f -", "/sbin/pfctl -E", "/usr/sbin/sysctl -w net.inet.ip.forwarding=1"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in\n%s", want, joined)
		}
	}
	if strings.Index(joined, "-n -a") > strings.Index(joined, "pfctl -a com.apple/yuhaiin -f -") {
		t.Fatal("rules loaded before the dry run")
	}
	// Same plan: nothing reloaded.
	f.calls = nil
	if err := m.Apply(darwinPlan()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(f.calls, "\n"), "pfctl") {
		t.Fatalf("unchanged plan reloaded PF: %v", f.calls)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(f.calls, "\n")
	if !strings.Contains(joined, "/sbin/pfctl -a com.apple/yuhaiin -F all") || !strings.Contains(joined, "/sbin/pfctl -X 1234567") || f.sysctl[darwinSysctlIPv4] != "0" {
		t.Fatalf("close = %s, sysctl %v", joined, f.sysctl)
	}
	if strings.Contains(joined, "pfctl -d") || strings.Contains(joined, "-F all\n/sbin/pfctl -a com.apple") {
		t.Fatal("global PF state changed")
	}
}

func TestDarwinRefusesCustomizedPFAndInvalidRules(t *testing.T) {
	m, f := newFake(false)
	if err := m.Apply(darwinPlan()); err == nil || !strings.Contains(err.Error(), "com.apple/*") {
		t.Fatalf("missing anchors not reported: %v", err)
	}
	if strings.Contains(strings.Join(f.calls, "\n"), "-a com.apple/yuhaiin -f") || f.sysctl[darwinSysctlIPv4] != "0" {
		t.Fatal("rules or sysctls applied without an evaluating anchor")
	}
	m, f = newFake(true)
	f.reject = true
	if err := m.Apply(darwinPlan()); err == nil {
		t.Fatal("rejected ruleset reported as applied")
	}
	for _, call := range f.calls {
		if call == "/sbin/pfctl -a com.apple/yuhaiin -f -" {
			t.Fatal("rejected ruleset loaded")
		}
	}
}
