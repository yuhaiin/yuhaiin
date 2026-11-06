package resolver

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"codeberg.org/miekg/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestUncachedFailureRetriesOnNextLookup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var attempts atomic.Int32
		offline := errors.New("offline")
		c := NewClient(Config{Name: "offline-test"}, TransportFunc(func(context.Context, *Request) (*dns.Msg, error) {
			attempts.Add(1)
			return nil, offline
		})).(*client)
		defer c.Close()
		q := netapi.DNSQuestion{Name: "uncached.example.", Qtype: dns.TypeA}
		for range 100 {
			msg, err := c.Raw(t.Context(), q)
			if msg != nil || !errors.Is(err, offline) {
				t.Fatalf("lookup should retain the upstream error, not fabricate an answer: msg=%v err=%v", msg, err)
			}
		}
		if got := attempts.Load(); got != 100 {
			t.Fatalf("100 sequential uncached lookups made %d upstream attempts, want 100", got)
		}
		if entries := c.DNSCacheEntries(); len(entries) != 0 {
			t.Fatalf("transport failure became a DNS answer: %v", entries)
		}
	})
}

func TestUncachedFailureDeduplicatesOnlyConcurrentLookups(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var attempts atomic.Int32
		release := make(chan struct{})
		offline := errors.New("offline")
		c := NewClient(Config{Name: "offline-test"}, TransportFunc(func(context.Context, *Request) (*dns.Msg, error) {
			attempts.Add(1)
			<-release
			return nil, offline
		})).(*client)
		defer c.Close()
		q := netapi.DNSQuestion{Name: "uncached.example.", Qtype: dns.TypeA}
		for range 100 {
			go func() {
				if _, err := c.Raw(t.Context(), q); !errors.Is(err, offline) {
					t.Errorf("concurrent lookup lost upstream failure: %v", err)
				}
			}()
		}
		synctest.Wait()
		if got := attempts.Load(); got != 1 {
			t.Fatalf("concurrent uncached lookups started %d requests, want 1", got)
		}
		close(release)
		synctest.Wait()
		for range 100 {
			if _, err := c.Raw(t.Context(), q); !errors.Is(err, offline) {
				t.Fatal(err)
			}
		}
		if got := attempts.Load(); got != 101 {
			t.Fatalf("later lookups retained the previous failure: attempts=%d want 101", got)
		}
	})
}

func TestUncachedCancellationDoesNotBlockNextLookup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		attempts := 0
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		c := NewClient(Config{Name: "offline-test"}, TransportFunc(func(ctx context.Context, req *Request) (*dns.Msg, error) {
			attempts++
			if attempts == 1 {
				cancel()
				return nil, ctx.Err()
			}
			return recoveryResponse(req), nil
		})).(*client)
		defer c.Close()
		q := netapi.DNSQuestion{Name: "uncached.example.", Qtype: dns.TypeA}
		if _, err := c.Raw(ctx, q); !errors.Is(err, context.Canceled) {
			t.Fatalf("expected caller cancellation, got %v", err)
		}
		if _, err := c.Raw(t.Context(), q); err != nil {
			t.Fatalf("canceled lookup poisoned subsequent lookup: %v", err)
		}
		if attempts != 2 {
			t.Fatalf("cancellation did not permit an immediate retry: attempts=%d want 2", attempts)
		}
	})
}
