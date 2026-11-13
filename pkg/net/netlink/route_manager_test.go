package netlink

import (
	"errors"
	"fmt"
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

func via(link int, gateway string, values ...string) []SystemRoute {
	var out []SystemRoute
	for _, p := range prefixes(values...) {
		r := SystemRoute{Prefix: p, Link: link}
		if gateway != "" {
			r.Gateway = netip.MustParseAddr(gateway)
		}
		out = append(out, r)
	}
	return out
}

type fakeRouteBackend struct {
	mu                  sync.Mutex
	routes              map[netip.Prefix]SystemRoute
	borrowed            map[netip.Prefix]bool
	failAdd, failDelete map[netip.Prefix]bool
	foreign             map[netip.Prefix]bool
	events              []string
	closes              int
}

func routeBackendForTest() *fakeRouteBackend {
	return &fakeRouteBackend{routes: map[netip.Prefix]SystemRoute{}, borrowed: map[netip.Prefix]bool{}, failAdd: map[netip.Prefix]bool{}, failDelete: map[netip.Prefix]bool{}, foreign: map[netip.Prefix]bool{}}
}

func (b *fakeRouteBackend) Add(r SystemRoute) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, "add "+r.String())
	if b.failAdd[r.Prefix] {
		return false, errors.New("injected add failure")
	}
	if b.foreign[r.Prefix] {
		return false, fmt.Errorf("%w: injected", ErrRouteConflict)
	}
	b.routes[r.Prefix] = r
	return !b.borrowed[r.Prefix], nil
}

func (b *fakeRouteBackend) Delete(r SystemRoute) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, "delete "+r.String())
	if b.borrowed[r.Prefix] {
		panic("deleted a borrowed route")
	}
	if b.failDelete[r.Prefix] {
		return errors.New("injected delete failure")
	}
	delete(b.routes, r.Prefix)
	return nil
}

func (b *fakeRouteBackend) Close() error { b.closes++; return nil }

type replacingBackend struct{ *fakeRouteBackend }

func (b replacingBackend) Replace(old, new SystemRoute) error {
	b.events = append(b.events, "replace "+old.String()+" -> "+new.String())
	if b.failAdd[new.Prefix] {
		return errors.New("injected replace failure")
	}
	b.routes[new.Prefix] = new
	return nil
}

func TestRouteManagerMultipleTargetsAndOwnership(t *testing.T) {
	b := routeBackendForTest()
	m := newRouteManager(b)
	tunA := via(10, "", "0.0.0.0/1", "128.0.0.0/1", "::/1")
	wg := via(20, "", "10.10.0.0/16")
	lan := via(2, "192.168.1.1", "203.0.113.0/24")
	b.borrowed[lan[0].Prefix] = true // an identical route already existed
	desired := append(append(append([]SystemRoute(nil), tunA...), wg...), lan...)
	if _, err := m.Update(desired); err != nil {
		t.Fatal(err)
	}
	if len(b.routes) != 5 || b.routes[lan[0].Prefix].Gateway != netip.MustParseAddr("192.168.1.1") || b.routes[wg[0].Prefix].Link != 20 {
		t.Fatalf("routes = %v", b.routes)
	}
	b.events = nil
	if _, err := m.Update(desired); err != nil || len(b.events) != 0 {
		t.Fatalf("unchanged update reinstalled routes: %v %v", b.events, err)
	}
	if !reflect.DeepEqual(m.Installed(), []SystemRoute{tunA[0], wg[0], tunA[1], lan[0], tunA[2]}) {
		t.Fatalf("installed = %v", m.Installed())
	}
	// Dropping the borrowed route forgets it without deleting it.
	if _, err := m.Update(desired[:4]); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.routes[lan[0].Prefix]; !ok {
		t.Fatal("borrowed route was deleted")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if len(b.routes) != 1 || b.closes != 1 {
		t.Fatalf("after close routes = %v closes = %d", b.routes, b.closes)
	}
	if _, err := m.Update(desired); err == nil {
		t.Fatal("updated a closed manager")
	}
}

func TestRouteManagerRejectsAmbiguousTargets(t *testing.T) {
	m := newRouteManager(routeBackendForTest())
	if _, err := m.Update(append(via(1, "", "192.0.2.0/24"), via(2, "", "192.0.2.0/24")...)); err == nil {
		t.Fatal("one prefix accepted for two targets")
	}
	if _, err := m.Update(via(0, "", "192.0.2.0/24")); err == nil {
		t.Fatal("route without an interface accepted")
	}
}

func TestRouteManagerTargetChange(t *testing.T) {
	for name, replace := range map[string]bool{"delete and add": false, "replace": true} {
		t.Run(name, func(t *testing.T) {
			fake := routeBackendForTest()
			var backend routeBackend = fake
			if replace {
				backend = replacingBackend{fake}
			}
			m := newRouteManager(backend)
			if _, err := m.Update(via(10, "", "8.8.8.8/32")); err != nil {
				t.Fatal(err)
			}
			// TUN A -> wg0, then a failing update rolls back to wg0.
			if _, err := m.Update(via(20, "", "8.8.8.8/32")); err != nil {
				t.Fatal(err)
			}
			if fake.routes[netip.MustParsePrefix("8.8.8.8/32")].Link != 20 {
				t.Fatalf("target not changed: %v", fake.routes)
			}
			next := append(via(30, "", "8.8.8.8/32"), via(30, "", "9.9.9.9/32")...)
			fake.failAdd[netip.MustParsePrefix("9.9.9.9/32")] = true
			if _, err := m.Update(next); err == nil {
				t.Fatal("missing add error")
			}
			if got := m.Installed(); !reflect.DeepEqual(got, via(20, "", "8.8.8.8/32")) {
				t.Fatalf("rollback left %v", got)
			}
			if fake.routes[netip.MustParsePrefix("8.8.8.8/32")].Link != 20 {
				t.Fatalf("OS route not restored: %v", fake.routes)
			}
		})
	}
}

func TestRouteManagerAddRollbackAndRetry(t *testing.T) {
	b := routeBackendForTest()
	m := newRouteManager(b)
	old := via(10, "", "198.18.0.0/16")
	if _, err := m.Update(old); err != nil {
		t.Fatal(err)
	}
	next := via(10, "", "198.19.0.0/16", "2001:2::/64")
	b.failAdd[next[1].Prefix] = true
	b.failDelete[next[0].Prefix] = true // rollback also fails; keep its cleanup record
	if _, err := m.Update(next); err == nil {
		t.Fatal("missing add error")
	}
	if _, ok := b.routes[old[0].Prefix]; !ok {
		t.Fatal("previous route lost after a failed update")
	}
	if _, ok := m.installed[next[0].Prefix]; !ok {
		t.Fatal("failed rollback deletion not tracked for retry")
	}
	delete(b.failDelete, next[0].Prefix)
	if _, err := m.Update(old); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.routes[next[0].Prefix]; ok {
		t.Fatal("rollback deletion was not retried")
	}
	delete(b.failAdd, next[1].Prefix)
	if _, err := m.Update(next); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.routes[old[0].Prefix]; ok {
		t.Fatal("stale route kept after a successful retry")
	}
}

func TestRouteManagerDeleteFailureAndCloseRetry(t *testing.T) {
	b := routeBackendForTest()
	m := newRouteManager(b)
	r := via(10, "", "198.18.0.0/16")
	if _, err := m.Update(r); err != nil {
		t.Fatal(err)
	}
	b.failDelete[r[0].Prefix] = true
	if _, err := m.Update(nil); err == nil {
		t.Fatal("missing delete error")
	}
	if err := m.Close(); err == nil || b.closes != 0 {
		t.Fatal("close released state while route cleanup was pending")
	}
	delete(b.failDelete, r[0].Prefix)
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if len(b.routes) != 0 || b.closes != 1 {
		t.Fatal("close did not retry cleanup")
	}
}

func TestRouteManagerYieldsConflictsToExistingRoutes(t *testing.T) {
	b := routeBackendForTest()
	m := newRouteManager(b)
	routes := via(10, "", "1.0.0.0/8", "2.0.0.0/8", "100.64.0.0/10", "::/1", "8000::/1")
	b.foreign[routes[2].Prefix] = true // e.g. Tailscale already routes 100.64.0.0/10
	b.foreign[routes[4].Prefix] = true
	conflicts, err := m.Update(routes)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(conflicts, prefixes("100.64.0.0/10", "8000::/1")) || len(b.routes) != 3 {
		t.Fatalf("conflicts = %v, routes = %v", conflicts, b.routes)
	}
	// After a network change the other route is gone: retried.
	delete(b.foreign, routes[2].Prefix)
	b.events = nil
	if conflicts, err = m.Update(routes); err != nil || !reflect.DeepEqual(conflicts, prefixes("8000::/1")) {
		t.Fatalf("retry conflicts = %v, %v", conflicts, err)
	}
	if len(b.events) != 2 {
		t.Fatalf("retry events = %v", b.events)
	}
	b.events = nil
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if len(b.routes) != 0 || len(b.events) != 4 {
		t.Fatalf("cleanup events = %v, remaining %v", b.events, b.routes)
	}
}

func TestRouteManagerConcurrentUpdateClose(t *testing.T) {
	b := routeBackendForTest()
	m := newRouteManager(b)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for range 100 {
				_, _ = m.Update(via(10+i%2, "", "198.18.0.0/16", "2001:2::/64"))
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
