package resolver

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestUncachedFailureDoesNotRetryEveryLookup(t *testing.T) {
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
			msg, err := c.Raw(context.Background(), q)
			if msg != nil || !errors.Is(err, offline) {
				t.Fatalf("lookup should retain the upstream error, not fabricate an answer: msg=%v err=%v", msg, err)
			}
		}
		if got := attempts.Load(); got != 1 {
			t.Fatalf("100 uncached lookups while offline made %d upstream attempts, want 1", got)
		}
		if entries := c.DNSCacheEntries(); len(entries) != 0 {
			t.Fatalf("transport failure became a DNS answer: %v", entries)
		}
	})
}

func uncachedRetryResponse(req *Request) *dns.Msg {
	// A short TTL keeps this a cache-miss test even after recovery.
	return &dns.Msg{ID: req.ID, Response: true, Rcode: dns.RcodeSuccess,
		Answer: []dns.RR{&dns.A{Hdr: dns.Header{Name: req.Question.Name, Class: dns.ClassINET, TTL: 1}, Addr: netip.MustParseAddr("192.0.2.1")}},
	}
}

func TestUncachedFailureBackoffRecoversAndResets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var attempts int
		online := false
		offline := errors.New("offline")
		c := NewClient(Config{Name: "offline-test"}, TransportFunc(func(_ context.Context, req *Request) (*dns.Msg, error) {
			attempts++
			if !online {
				return nil, offline
			}
			return uncachedRetryResponse(req), nil
		})).(*client)
		defer c.Close()
		q := netapi.DNSQuestion{Name: "uncached.example.", Qtype: dns.TypeA}
		lookupFailed := func() {
			t.Helper()
			if _, err := c.Raw(context.Background(), q); !errors.Is(err, offline) {
				t.Fatalf("expected offline error, got %v", err)
			}
		}
		lookupFailed()
		expected := 1
		for _, delay := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 5 * time.Second, 5 * time.Second} {
			time.Sleep(delay - time.Nanosecond)
			lookupFailed()
			if attempts != expected {
				t.Fatalf("retry before %s cooldown: attempts=%d want %d", delay, attempts, expected)
			}
			time.Sleep(time.Nanosecond)
			lookupFailed()
			expected++
			if attempts != expected {
				t.Fatalf("cooldown elapsed: attempts=%d want %d", attempts, expected)
			}
		}
		online = true
		time.Sleep(5 * time.Second)
		if msg, err := c.Raw(context.Background(), q); err != nil || len(msg.Answer) != 1 {
			t.Fatalf("recovered upstream did not return an answer: msg=%v err=%v", msg, err)
		}
		expected++
		online = false
		lookupFailed()
		expected++
		time.Sleep(time.Second)
		lookupFailed()
		expected++
		if attempts != expected {
			t.Fatalf("success did not reset initial cooldown: attempts=%d want %d", attempts, expected)
		}
	})
}

func TestUncachedFailureIsSharedAcrossConcurrentAndLaterLookups(t *testing.T) {
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
				if _, err := c.Raw(context.Background(), q); !errors.Is(err, offline) {
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
			if _, err := c.Raw(context.Background(), q); !errors.Is(err, offline) {
				t.Fatal(err)
			}
		}
		if got := attempts.Load(); got != 1 {
			t.Fatalf("later lookups bypassed published failure: attempts=%d want 1", got)
		}
	})
}

func TestUncachedFailureIsScopedAndExplicitlyClearable(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		attempts := 0
		offline := errors.New("offline")
		c := NewClient(Config{Name: "offline-test"}, TransportFunc(func(_ context.Context, req *Request) (*dns.Msg, error) {
			attempts++
			if req.Question.Name == "other.example." {
				return uncachedRetryResponse(req), nil
			}
			return nil, offline
		})).(*client)
		defer c.Close()
		q := netapi.DNSQuestion{Name: "uncached.example.", Qtype: dns.TypeA}
		lookupFailed := func(q netapi.DNSQuestion) {
			t.Helper()
			if _, err := c.Raw(context.Background(), q); !errors.Is(err, offline) {
				t.Fatal(err)
			}
		}
		lookupFailed(q)
		lookupFailed(q)
		if _, err := c.Raw(context.Background(), netapi.DNSQuestion{Name: "other.example.", Qtype: dns.TypeA}); err != nil {
			t.Fatalf("unrelated question was blocked: %v", err)
		}
		v6 := q
		v6.Qtype = dns.TypeAAAA
		lookupFailed(v6)
		if attempts != 3 {
			t.Fatalf("failure cooldown leaked to other questions: attempts=%d want 3", attempts)
		}
		if removed := c.ClearDNSCache("Uncached.EXAMPLE"); removed != 0 {
			t.Fatalf("transport errors counted as cached DNS answers: removed=%d", removed)
		}
		lookupFailed(q)
		lookupFailed(v6)
		if attempts != 5 {
			t.Fatalf("cache clearing did not allow an immediate retry for all types: attempts=%d want 5", attempts)
		}
	})
}

func TestUncachedCancellationDoesNotBlockNextLookup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		attempts := 0
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		c := NewClient(Config{Name: "offline-test"}, TransportFunc(func(ctx context.Context, req *Request) (*dns.Msg, error) {
			attempts++
			if attempts == 1 {
				cancel()
				return nil, ctx.Err()
			}
			return uncachedRetryResponse(req), nil
		})).(*client)
		defer c.Close()
		q := netapi.DNSQuestion{Name: "uncached.example.", Qtype: dns.TypeA}
		if _, err := c.Raw(ctx, q); !errors.Is(err, context.Canceled) {
			t.Fatalf("expected caller cancellation, got %v", err)
		}
		if _, err := c.Raw(context.Background(), q); err != nil {
			t.Fatalf("canceled lookup poisoned subsequent lookup: %v", err)
		}
		if attempts != 2 {
			t.Fatalf("cancellation did not permit an immediate retry: attempts=%d want 2", attempts)
		}
	})
}

func TestUncachedTimeoutBacksOff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		attempts := 0
		c := NewClient(Config{Name: "offline-test"}, TransportFunc(func(ctx context.Context, req *Request) (*dns.Msg, error) {
			attempts++
			if attempts == 1 {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return uncachedRetryResponse(req), nil
		})).(*client)
		defer c.Close()
		q := netapi.DNSQuestion{Name: "uncached.example.", Qtype: dns.TypeA}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := c.Raw(ctx, q); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected timeout, got %v", err)
		}
		if _, err := c.Raw(context.Background(), q); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected retained timeout during cooldown, got %v", err)
		}
		if attempts != 1 {
			t.Fatalf("timeout did not throttle next lookup: attempts=%d want 1", attempts)
		}
		time.Sleep(time.Second)
		if _, err := c.Raw(context.Background(), q); err != nil {
			t.Fatalf("retry after timeout cooldown failed: %v", err)
		}
	})
}
