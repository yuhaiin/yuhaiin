package netlink

import (
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"testing"
)

func prefixes(values ...string) []netip.Prefix {
	var result []netip.Prefix
	for _, v := range values {
		result = append(result, netip.MustParsePrefix(v))
	}
	return result
}

func TestNormalizeRoutes(t *testing.T) {
	for _, tt := range []struct {
		name        string
		input, want []string
	}{
		{"dual stack", []string{"2001:2::1/64", "198.18.0.1/16", "198.18.0.0/24", "198.18.0.0/16", "2001:2::/80"}, []string{"198.18.0.0/16", "2001:2::/64"}},
		{"larger arrives later", []string{"198.18.1.0/24", "198.18.0.0/15"}, []string{"198.18.0.0/15"}},
		{"default routes", []string{"198.18.0.0/16", "0.0.0.0/0", "2001:2::/64", "::/0"}, []string{"0.0.0.0/0", "::/0"}},
		{"adjacent stays separate", []string{"198.18.0.0/16", "198.19.0.0/16"}, []string{"198.18.0.0/16", "198.19.0.0/16"}},
		{"hosts", []string{"198.18.0.1/32", "2001:2::1/128", "198.18.0.1/32"}, []string{"198.18.0.1/32", "2001:2::1/128"}},
		{"empty", nil, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeRoutes(prefixes(tt.input...))
			if !reflect.DeepEqual(got, prefixes(tt.want...)) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
	if got := NormalizeRoutes([]netip.Prefix{{}}); len(got) != 0 {
		t.Fatalf("invalid prefix retained: %v", got)
	}
}

type fakeRouteBackend struct {
	routes              map[netip.Prefix]bool
	borrowed            map[netip.Prefix]bool
	failAdd, failDelete map[netip.Prefix]bool
	events              []string
	closes              int
}

func routeBackendForTest() *fakeRouteBackend {
	return &fakeRouteBackend{routes: make(map[netip.Prefix]bool), borrowed: make(map[netip.Prefix]bool), failAdd: make(map[netip.Prefix]bool), failDelete: make(map[netip.Prefix]bool)}
}

func (b *fakeRouteBackend) Add(p netip.Prefix) (bool, error) {
	b.events = append(b.events, "add "+p.String())
	if b.failAdd[p] {
		return false, errors.New("injected add failure")
	}
	b.routes[p] = true
	return !b.borrowed[p], nil
}
func (b *fakeRouteBackend) Delete(p netip.Prefix) error {
	b.events = append(b.events, "delete "+p.String())
	if b.borrowed[p] {
		panic("deleted a borrowed route")
	}
	if b.failDelete[p] {
		return errors.New("injected delete failure")
	}
	delete(b.routes, p)
	return nil
}
func (b *fakeRouteBackend) Close(pending bool) error {
	if !pending {
		b.closes++
	}
	return nil
}

func TestRouteManagerUpdateAndOwnership(t *testing.T) {
	b := routeBackendForTest()
	m := newRouteManager(b)
	old := prefixes("198.18.0.0/16", "2001:2::/64")
	b.borrowed[old[0]] = true
	if err := m.Update(old); err != nil {
		t.Fatal(err)
	}
	b.events = nil
	if err := m.Update(old); err != nil {
		t.Fatal(err)
	}
	if len(b.events) != 0 {
		t.Fatalf("unchanged routes were reinstalled: %v", b.events)
	}
	if err := m.Update(prefixes("198.19.0.0/16", "2001:2:0:1::/64")); err != nil {
		t.Fatal(err)
	}
	want := []string{"add 198.19.0.0/16", "add 2001:2:0:1::/64", "delete 2001:2::/64"}
	if !reflect.DeepEqual(b.events, want) {
		t.Fatalf("events %v, want %v", b.events, want)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if len(b.routes) != 1 || !b.routes[old[0]] {
		t.Fatalf("borrowed route not preserved: %v", b.routes)
	}
	if err := m.Update(old); err == nil {
		t.Fatal("updated a closed manager")
	}
}

func TestRouteManagerAddRollbackAndRetry(t *testing.T) {
	b := routeBackendForTest()
	m := newRouteManager(b)
	old := prefixes("198.18.0.0/16")
	if err := m.Update(old); err != nil {
		t.Fatal(err)
	}
	next := prefixes("198.19.0.0/16", "2001:2::/64")
	b.failAdd[next[1]] = true
	b.failDelete[next[0]] = true // rollback also fails; retain its cleanup record
	if err := m.Update(next); err == nil {
		t.Fatal("missing add error")
	}
	if !b.routes[old[0]] || !m.installed[next[0]] {
		t.Fatalf("lost old route or failed rollback record: %v", m.installed)
	}
	delete(b.failDelete, next[0])
	if err := m.Update(old); err != nil {
		t.Fatal(err)
	}
	if b.routes[next[0]] {
		t.Fatal("rollback was not retried")
	}
	delete(b.failAdd, next[1])
	if err := m.Update(next); err != nil {
		t.Fatal(err)
	}
	if b.routes[old[0]] {
		t.Fatal("stale route retained after successful retry")
	}
}

func TestRouteManagerDeleteFailureAndCloseRetry(t *testing.T) {
	b := routeBackendForTest()
	m := newRouteManager(b)
	p := prefixes("198.18.0.0/16")[0]
	if err := m.Update([]netip.Prefix{p}); err != nil {
		t.Fatal(err)
	}
	b.failDelete[p] = true
	if err := m.Update(nil); err == nil {
		t.Fatal("missing delete error")
	}
	if !m.installed[p] {
		t.Fatal("lost failed deletion record")
	}
	if err := m.Close(); err == nil {
		t.Fatal("missing close error")
	}
	if b.closes != 0 {
		t.Fatal("released policy rules while route cleanup was pending")
	}
	delete(b.failDelete, p)
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if len(b.routes) != 0 || b.closes != 1 {
		t.Fatal("close did not retry cleanup")
	}
}

func TestRouteManagerConcurrentUpdateClose(t *testing.T) {
	b := routeBackendForTest()
	m := newRouteManager(b)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				_ = m.Update(prefixes("198.18.0.0/16", "2001:2::/64"))
			}
		})
	}
	wg.Go(func() { _ = m.Close() })
	wg.Wait()
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if len(b.routes) != 0 {
		t.Fatalf("routes remain after close: %v", b.routes)
	}
}

func TestRouteManagerRequiredRoutesAndMultipleTUNs(t *testing.T) {
	b1, b2 := routeBackendForTest(), routeBackendForTest()
	m1, m2 := newRouteManager(b1), newRouteManager(b2)
	m1.required = prefixes("172.19.0.0/24")
	for _, m := range []*RouteManager{m1, m2} {
		if err := m.Update(prefixes("198.18.0.0/16")); err != nil {
			t.Fatal(err)
		}
	}
	if err := m1.Update(nil); err != nil {
		t.Fatal(err)
	}
	if !b1.routes[m1.required[0]] {
		t.Fatal("required interface route was removed")
	}
	if err := m1.Close(); err != nil {
		t.Fatal(err)
	}
	if len(b2.routes) != 1 {
		t.Fatal("closing one TUN modified another TUN")
	}
}
