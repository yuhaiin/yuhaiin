package netstate

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func network(id, name string, index int, addresses ...string) Network {
	n := Network{ID: id, Name: name, Index: index, Available: true}
	for _, address := range addresses {
		n.Addresses = append(n.Addresses, netip.MustParseAddr(address))
	}
	return n
}

func startManager(t *testing.T, m *Manager) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); m.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("cleanup worker leaked")
		}
	})
}

func receive(t *testing.T, ch <-chan Event) Event {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(time.Second):
		t.Fatal("missing invalidation")
		return Event{}
	}
}

func TestRouteActivityNeverInvalidatesPaths(t *testing.T) {
	m := NewManager()
	s := Snapshot{Networks: []Network{network("ifindex:2", "wifi", 2, "192.0.2.2", "2001:db8::2")}}
	initial := m.Apply(s, false)
	p := m.Capture("wifi", netip.MustParseAddr("192.0.2.2"), 4)
	if !p.Known() {
		t.Fatal("source affinity not captured")
	}
	var called atomic.Int32
	r := m.Register(p, func(Event) { called.Add(1) })
	defer r.Close()
	startManager(t, m)
	for _, scenario := range []string{"add host route", "remove unused route", "metric", "gateway", "VPN route", "split tunnel", "policy table", "IPv6 route", "normal traffic", "route reorder", "DNS configuration", "unchanged route cache"} {
		t.Run(scenario, func(t *testing.T) {
			for range 100 {
				e := m.Apply(s, true)
				if e.Changes != RouteChanged || e.Generation != initial.Generation || !m.Valid(p) {
					t.Fatalf("route-only observation changed path: %+v", e)
				}
			}
		})
	}
	_, err := m.Refresh(func() (Snapshot, error) { return Snapshot{}, errors.New("temporary snapshot failure") }, true)
	if err == nil || !m.Valid(p) || called.Load() != 0 {
		t.Fatal("unknown state invalidated a healthy socket")
	}
}

func TestSelectiveAddressAndFamilyInvalidation(t *testing.T) {
	m := NewManager()
	wifi := network("wifi", "wlan0", 2, "192.0.2.2", "2001:db8::2")
	cell := network("cell", "rmnet0", 3, "198.51.100.2")
	s := Snapshot{Networks: []Network{wifi, cell}}
	m.Apply(s, false)
	v4 := m.Capture("wlan0", netip.MustParseAddr("192.0.2.2"), 4)
	v6 := m.Capture("wlan0", netip.MustParseAddr("2001:db8::2"), 6)
	other := m.Capture("rmnet0", netip.Addr{}, 4)
	wild4 := m.Capture("wlan0", netip.Addr{}, 4)
	wild6 := m.Capture("wlan0", netip.Addr{}, 6)
	ch := make(chan Event, 4)
	for _, p := range []Path{v4, v6, other, wild4, wild6} {
		r := m.Register(p, func(e Event) { ch <- e })
		defer r.Close()
	}
	startManager(t, m)
	wifi.Addresses[0] = netip.MustParseAddr("192.0.2.3")
	m.Apply(Snapshot{Networks: []Network{wifi, cell}}, false)
	receive(t, ch)
	receive(t, ch)
	if m.Valid(v4) || m.Valid(wild4) || !m.Valid(v6) || !m.Valid(wild6) || !m.Valid(other) {
		t.Fatal("IPv4 renewal affected unrelated family/network")
	}
	select {
	case <-ch:
		t.Fatal("unaffected socket closed")
	default:
	}
	// Later IPv6-only replacement must leave the renewed IPv4 path usable.
	new4 := m.Capture("wlan0", netip.MustParseAddr("192.0.2.3"), 4)
	wifi.Addresses[1] = netip.MustParseAddr("2001:db8::3")
	m.Apply(Snapshot{Networks: []Network{wifi, cell}}, false)
	receive(t, ch)
	receive(t, ch)
	if m.Valid(v6) || !m.Valid(new4) || !m.Valid(other) {
		t.Fatal("IPv6 renewal invalidation is not selective")
	}
}

func TestTransitionsRetainHealthyIndependentNetworks(t *testing.T) {
	for _, pair := range [][2]string{{"wifi", "cell"}, {"cell", "wifi"}, {"ethernet", "wifi"}} {
		t.Run(pair[0]+" to "+pair[1], func(t *testing.T) {
			m := NewManager()
			a := network(pair[0], "if0", 2, "192.0.2.2")
			b := network(pair[1], "if1", 3, "198.51.100.2")
			s := Snapshot{Networks: []Network{a, b}, Selected: a.ID, Source: PlatformCallback}
			m.Apply(s, false)
			old := m.Capture("if0", netip.Addr{}, 4)
			other := m.Capture("if1", netip.Addr{}, 4)
			s.Selected = b.ID
			e := m.Apply(s, true)
			if e.Changes&NetworkChanged == 0 || !m.Valid(old) || !m.Valid(other) {
				t.Fatal("selection alone killed healthy bound connections")
			}
			a.Available = false
			s.Networks = []Network{a, b}
			e = m.Apply(s, false)
			if e.Changes != ConnectivityChanged || m.Valid(old) || !m.Valid(other) {
				t.Fatal("loss of old network was not selective")
			}
			a.Available = true
			s.Networks = []Network{a, b}
			m.Apply(s, false)
			if m.Valid(old) || !m.Capture("if0", netip.Addr{}, 4).Known() {
				t.Fatal("restoration resurrected obsolete path tokens")
			}
		})
	}
}

func TestRapidABAAndStaleRegistration(t *testing.T) {
	m := NewManager()
	a := network("index:2", "same-name", 2, "192.0.2.2")
	m.Apply(Snapshot{Networks: []Network{a}}, false)
	old := m.Capture(a.Name, a.Addresses[0], 4)
	oldCalls := make(chan Event, 2)
	r := m.Register(old, func(e Event) { oldCalls <- e })
	defer r.Close()
	m.Apply(Snapshot{}, false)
	// Same name, ifindex and IP can be reused, but not the interface lifetime.
	m.Apply(Snapshot{Networks: []Network{a}}, false)
	newPath := m.Capture(a.Name, a.Addresses[0], 4)
	if m.Valid(old) || !m.Valid(newPath) {
		t.Fatal("interface recreation reused path token")
	}
	var newCalls atomic.Int32
	newReg := m.Register(newPath, func(Event) { newCalls.Add(1) })
	defer newReg.Close()
	late := m.Register(old, func(e Event) { oldCalls <- e })
	defer late.Close()
	startManager(t, m)
	receive(t, oldCalls)
	receive(t, oldCalls)
	if newCalls.Load() != 0 {
		t.Fatal("old cleanup closed a new connection")
	}
}

func TestRenamingAndPartialAddressChurn(t *testing.T) {
	m := NewManager()
	n := network("index:7", "before", 7, "192.0.2.2", "192.0.2.3")
	m.Apply(Snapshot{Networks: []Network{n}}, false)
	p := m.Capture(n.Name, netip.Addr{}, 4)
	specific := m.Capture(n.Name, n.Addresses[0], 4)
	n.Name = "after"
	m.Apply(Snapshot{Networks: []Network{n}}, false)
	if !m.Valid(p) || !m.Valid(specific) {
		t.Fatal("rename invalidated a stable interface")
	}
	n.Addresses = n.Addresses[1:]
	m.Apply(Snapshot{Networks: []Network{n}}, false)
	if !m.Valid(p) || m.Valid(specific) {
		t.Fatal("partial address loss was not conservatively selective")
	}
}

func TestUnknownSelectionIsNotAConfirmedSwitch(t *testing.T) {
	m := NewManager()
	a, b := network("a", "wifi", 2, "192.0.2.2"), network("b", "cell", 3, "198.51.100.2")
	s := Snapshot{Networks: []Network{a, b}, Selected: "a", Source: PlatformCallback}
	initial := m.Apply(s, false)
	s.Selected = ""
	if e := m.Apply(s, false); e.Generation != initial.Generation || e.Changes != 0 {
		t.Fatal("unknown selected path became a network transition")
	}
	if m.Capture("", netip.Addr{}, 4).Known() {
		t.Fatal("unknown selection guessed a default underlay")
	}
	s.Selected = "b"
	if e := m.Apply(s, false); e.Changes&NetworkChanged == 0 {
		t.Fatal("confirmed replacement after an unknown observation was lost")
	}
}

func TestIPInterfaceDeletionPreservesOtherFamily(t *testing.T) {
	m := NewManager()
	n := network("luid:1", "Ethernet", 2, "192.0.2.2", "2001:db8::2")
	m.Apply(Snapshot{Networks: []Network{n}}, false)
	v4 := m.Capture(n.Name, netip.Addr{}, 4)
	v6 := m.Capture(n.Name, netip.Addr{}, 6)
	m.FamilyUnavailable(2, 4)
	if m.Valid(v4) || !m.Valid(v6) {
		t.Fatal("IPv4 IP-interface deletion invalidated IPv6 adapter paths")
	}
	m.FamilyUnavailable(2, 6)
	if m.Valid(v6) {
		t.Fatal("IPv6 IP-interface deletion was ignored")
	}
}

func TestConcurrentRegistrationAndCallbackReentry(t *testing.T) {
	m := NewManager()
	s := Snapshot{Networks: []Network{network("a", "a", 2, "192.0.2.2")}}
	m.Apply(s, false)
	p := m.Capture("a", netip.Addr{}, 4)
	startManager(t, m)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 1000 {
				r := m.Register(p, func(Event) { _ = m.Register(Path{}, nil); _ = m.Valid(p) })
				_ = r.Close()
			}
		})
	}
	wg.Go(func() {
		for range 100 {
			m.Apply(Snapshot{}, false)
			m.Apply(s, false)
		}
	})
	wg.Wait()
	// No watcher is installed when the actual binding is unknown.
	if m.Register(Path{}, func(Event) { t.Error("unknown path closed") }) != nil {
		t.Fatal("unknown affinity retained")
	}
}

func BenchmarkUnchangedSnapshot(b *testing.B) {
	m := NewManager()
	s := Snapshot{Networks: []Network{network("a", "wlan0", 2, "192.0.2.2", "2001:db8::2")}}
	m.Apply(s, false)
	b.ReportAllocs()
	for b.Loop() {
		m.Apply(s, true)
	}
}

func BenchmarkRegistration(b *testing.B) {
	m := NewManager()
	m.Apply(Snapshot{Networks: []Network{network("a", "wlan0", 2, "192.0.2.2")}}, false)
	p := m.Capture("wlan0", netip.Addr{}, 4)
	b.ReportAllocs()
	for b.Loop() {
		r := m.Register(p, func(Event) {})
		_ = r.Close()
	}
}
