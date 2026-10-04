package resolver

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestFakednsDefaultPools(t *testing.T) {
	f, err := NewFakeDNS(
		netapi.NewErrProxy(errors.New("test dialer")),
		netapi.ErrorResolver(func(string) error { return nil }),
		t.TempDir()+"/state.db",
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	ipv4 := netip.MustParsePrefix("198.18.0.0/16")
	ipv6 := netip.MustParsePrefix("2001:2::/64")
	if !f.fake.Equal(ipv4, ipv6) {
		t.Fatal("constructor did not use the default benchmarking pools")
	}
	initial := f.fake
	f.Apply(contractresolver.FakeDNS{})
	if f.fake != initial {
		t.Fatal("applying empty settings replaced the default pools")
	}
}

func TestFakednsDispatchAddrConcurrentClose(t *testing.T) {
	f, err := NewFakeDNS(
		netapi.NewErrProxy(errors.New("test dialer")),
		netapi.ErrorResolver(func(string) error { return nil }),
		t.TempDir()+"/state.db",
	)
	if err != nil {
		t.Fatal(err)
	}

	addr, err := netapi.ParseAddress("tcp", "198.18.0.1:443")
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			<-start
			for range 1000 {
				_ = f.dispatchAddr(context.Background(), addr)
			}
		})
	}
	closed := make(chan struct{})
	go func() {
		<-start
		_ = f.Close()
		close(closed)
	}()

	close(start)
	wg.Wait()
	<-closed

	if got := f.dispatchAddr(context.Background(), addr); got != addr {
		t.Fatalf("dispatch after close returned %v, want original address %v", got, addr)
	}
}

func newFakeDNSForRoutes(t *testing.T) *Fakedns {
	t.Helper()
	f, err := NewFakeDNS(netapi.NewErrProxy(errors.New("test dialer")), netapi.ErrorResolver(func(string) error { return nil }), t.TempDir()+"/state.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestFakeIPRangeSubscriptionAndRetry(t *testing.T) {
	f := newFakeDNSForRoutes(t)
	var calls [][2]netip.Prefix
	fail := false
	unsubscribe, err := f.SubscribeFakeIPRanges(func(ranges [2]netip.Prefix) error {
		// Notifications must run outside fakeMu; querying the active pools is safe.
		if got := f.FakeIPRanges(); got != ranges {
			t.Fatalf("notification %v differs from active pools %v", ranges, got)
		}
		calls = append(calls, ranges)
		if fail {
			return errors.New("route update failed")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 {
		t.Fatal("missing initial snapshot")
	}
	config := contractresolver.FakeDNS{IPv4Range: "198.19.0.1/16", IPv6Range: "2001:2:0:1::/64"}
	fail = true
	if err := f.Apply(config); err == nil {
		t.Fatal("route sync error was swallowed")
	}
	want := [2]netip.Prefix{netip.MustParsePrefix("198.19.0.0/16"), netip.MustParsePrefix(config.IPv6Range)}
	if calls[len(calls)-1] != want {
		t.Fatalf("unexpected pools: %v", calls)
	}
	fail = false
	if err := f.Apply(config); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 {
		t.Fatal("unchanged settings did not retry synchronization")
	}
	unsubscribe()
	unsubscribe()
	if err := f.Apply(contractresolver.FakeDNS{}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 {
		t.Fatal("cancelled subscriber was notified")
	}
}

func TestFakeIPPoolFailureDoesNotNotifyRoutes(t *testing.T) {
	f := newFakeDNSForRoutes(t)
	var count int
	unsubscribe, err := f.SubscribeFakeIPRanges(func([2]netip.Prefix) error { count++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer unsubscribe()
	before := f.FakeIPRanges()
	// A directory cannot be opened as the replacement SQLite pool database.
	f.dbPath = t.TempDir()
	if err := f.Apply(contractresolver.FakeDNS{IPv4Range: "198.19.0.0/16", IPv6Range: "2001:2:0:1::/64"}); err == nil {
		t.Fatal("expected pool creation failure")
	}
	if count != 1 || f.FakeIPRanges() != before {
		t.Fatal("failed pool switch changed routes or active pools")
	}
}

func TestFakeIPSubscriptionConcurrentCancellationAndClose(t *testing.T) {
	f := newFakeDNSForRoutes(t)
	var callbacks atomic.Int32
	unsubscribe, err := f.SubscribeFakeIPRanges(func([2]netip.Prefix) error { callbacks.Add(1); return nil })
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 100 {
				_ = f.Apply(contractresolver.FakeDNS{})
			}
		})
	}
	wg.Go(unsubscribe)
	wg.Wait()
	before := callbacks.Load()
	if err := f.Apply(contractresolver.FakeDNS{}); err != nil {
		t.Fatal(err)
	}
	if callbacks.Load() != before {
		t.Fatal("callback started after cancellation returned")
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Apply(contractresolver.FakeDNS{}); err == nil {
		t.Fatal("applied settings after close")
	}
	if _, err := f.SubscribeFakeIPRanges(func([2]netip.Prefix) error { return nil }); err == nil {
		t.Fatal("subscribed after close")
	}
}
