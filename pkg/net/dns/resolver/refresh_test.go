package resolver

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
)

func expiredRefreshAnswer(c *client, name string) netapi.DNSQuestion {
	question := netapi.DNSQuestion{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.rawStore.Add(CacheKeyFromQuestion(question), &dns.Msg{
		Response: true, Rcode: dns.RcodeSuccess,
		Answer: []dns.RR{&dns.A{Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: 60}, Addr: netip.MustParseAddr("192.0.2.1")}},
	}, lru.WithTimeout[string, *dns.Msg](-time.Second))
	return question
}

func TestFailedBackgroundRefreshRetriesOnNextStaleLookup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var attempts atomic.Int32
		c := NewClient(Config{Name: "offline-test"}, TransportFunc(func(context.Context, *Request) (*dns.Msg, error) {
			attempts.Add(1)
			return nil, errors.New("offline")
		})).(*client)
		defer c.Close()
		q := expiredRefreshAnswer(c, "offline.example.")
		for range 100 {
			msg, err := c.Raw(t.Context(), q)
			if err != nil || len(msg.Answer) != 1 {
				t.Fatalf("stale answer unavailable: msg=%v err=%v", msg, err)
			}
			synctest.Wait()
		}
		if got := attempts.Load(); got != 100 {
			t.Fatalf("100 sequential stale lookups made %d upstream attempts, want 100", got)
		}
	})
}

func TestBackgroundRefreshConcurrencyIsBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var active atomic.Int32
		c := NewClient(Config{Name: "offline-test"}, TransportFunc(func(ctx context.Context, _ *Request) (*dns.Msg, error) {
			active.Add(1)
			defer active.Add(-1)
			<-ctx.Done()
			return nil, ctx.Err()
		})).(*client)
		defer c.Close()
		for i := range 20 {
			q := expiredRefreshAnswer(c, fmt.Sprintf("host-%d.example.", i))
			if _, err := c.Raw(t.Context(), q); err != nil {
				t.Fatal(err)
			}
		}
		synctest.Wait()
		if got := active.Load(); got > 4 || got == 0 {
			t.Fatalf("20 different expired questions started %d concurrent refreshes, want 1..4", got)
		}
	})
}

func TestClosingClientCancelsBackgroundRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var canceled atomic.Bool
		c := NewClient(Config{Name: "offline-test"}, TransportFunc(func(ctx context.Context, _ *Request) (*dns.Msg, error) {
			<-ctx.Done()
			canceled.Store(true)
			return nil, ctx.Err()
		})).(*client)
		q := expiredRefreshAnswer(c, "offline.example.")
		if _, err := c.Raw(t.Context(), q); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if !canceled.Load() {
			t.Fatal("closing the resolver left a detached refresh running")
		}
	})
}

func TestBackgroundRefreshFailureDoesNotBlockOtherQuestions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var attempts atomic.Int32
		c := NewClient(Config{Name: "offline-test"}, TransportFunc(func(_ context.Context, req *Request) (*dns.Msg, error) {
			attempts.Add(1)
			if req.Question.Name == "offline.example." {
				return nil, errors.New("offline")
			}
			return &dns.Msg{ID: req.ID, Response: true, Rcode: dns.RcodeSuccess,
				Answer: []dns.RR{&dns.A{Hdr: dns.Header{Name: req.Question.Name, Class: dns.ClassINET, TTL: 60}, Addr: netip.MustParseAddr("192.0.2.2")}},
			}, nil
		})).(*client)
		defer c.Close()
		q := expiredRefreshAnswer(c, "offline.example.")
		if _, err := c.Raw(t.Context(), q); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		fresh, err := c.Raw(t.Context(), netapi.DNSQuestion{Name: "new.example.", Qtype: dns.TypeA})
		if err != nil || fresh.Answer[0].(*dns.A).Addr.String() != "192.0.2.2" {
			t.Fatalf("foreground miss was blocked: answer=%v err=%v", fresh, err)
		}
		other := expiredRefreshAnswer(c, "other.example.")
		if _, err := c.Raw(t.Context(), other); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if got := attempts.Load(); got != 3 {
			t.Fatalf("other questions were blocked by failed refresh: attempts=%d want 3", got)
		}
		// Clearing stale data turns the next lookup into a foreground request.
		if removed := c.ClearDNSCache(q.Name); removed != 1 {
			t.Fatalf("removed %d records, want 1", removed)
		}
		if _, err := c.Raw(t.Context(), q); err == nil {
			t.Fatal("uncached offline request should report the upstream error")
		}
		if got := attempts.Load(); got != 4 {
			t.Fatalf("cache miss did not query upstream: attempts=%d want 4", got)
		}
	})
}

func TestBackgroundRefreshPreservesCallerValuesButEndsWithClient(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		type contextKey struct{}
		var ended atomic.Bool
		c := NewClient(Config{Name: "offline-test"}, TransportFunc(func(ctx context.Context, _ *Request) (*dns.Msg, error) {
			if got := ctx.Value(contextKey{}); got != "routing-context" {
				t.Errorf("refresh lost caller values: %v", got)
			}
			<-ctx.Done()
			ended.Store(true)
			return nil, ctx.Err()
		})).(*client)
		defer c.Close()
		ctx, cancel := context.WithCancel(context.WithValue(t.Context(), contextKey{}, "routing-context"))
		q := expiredRefreshAnswer(c, "offline.example.")
		if _, err := c.Raw(ctx, q); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		cancel()
		synctest.Wait()
		if ended.Load() {
			t.Fatal("finishing the original lookup canceled optional background refresh")
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if !ended.Load() {
			t.Fatal("client close did not cancel refresh")
		}
		if _, err := c.Raw(t.Context(), q); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
	})
}
