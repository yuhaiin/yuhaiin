package fakeip

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
)

func TestFakeIPEntriesPagingSearchAndDeletion(t *testing.T) {
	v4, db := newTestSQLiteFakeIPPool(t, netip.MustParsePrefix("198.18.0.0/16"), 1000)
	v6, err := newSQLiteFakeIPPool(db, netip.MustParsePrefix("2001:2::/64"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v6.Close() })
	f := &FakeDNS{ipv4: v4, ipv6: v6}
	for i := range 105 {
		v4.GetFakeIPForDomain(fmt.Sprintf("host-%03d.example", i))
	}
	v6IP := v6.GetFakeIPForDomain("host-000.example")
	stale, err := newSQLiteFakeIPPool(db, netip.MustParsePrefix("10.0.0.0/24"), 100)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stale.Close() })
	stale.GetFakeIPForDomain("inactive.example")
	items, total, err := f.ListEntries(t.Context(), 2, 25, "")
	if err != nil || total != 106 || len(items) != 25 || items[0].Domain != "host-025.example" {
		t.Fatalf("page = %v %d %v", items, total, err)
	}
	for _, tt := range []struct{ page, size, want int }{{0, 0, 25}, {1, -1, 25}, {1, 99999, 100}, {5, 25, 6}, {6, 25, 0}, {int(^uint(0) >> 1), 100, 0}} {
		items, total, err := f.ListEntries(t.Context(), tt.page, tt.size, "")
		if err != nil || total != 106 || len(items) != tt.want {
			t.Fatalf("page %v: len=%d total=%d err=%v", tt, len(items), total, err)
		}
	}
	for _, tt := range []struct {
		query string
		want  int
	}{{" HOST-000.Example ", 2}, {"198.18.0.1", 1}, {"2001:0002:0000:0000:0000:0000:0000:0000", 1}, {"%", 0}, {"_", 0}, {"' OR 1=1 --", 0}, {"inactive", 0}, {"missing", 0}} {
		items, total, err := f.ListEntries(t.Context(), 1, 25, tt.query)
		if err != nil || total != tt.want || len(items) != tt.want {
			t.Fatalf("search %q: items=%v total=%d err=%v", tt.query, items, total, err)
		}
	}
	first := contractresolver.FakeIPEntry{Domain: "host-000.example", IP: "198.18.0.0"}
	// A changed IP or domain must not remove the displayed mapping.
	for _, entry := range []contractresolver.FakeIPEntry{{Domain: first.Domain, IP: "198.18.0.1"}, {Domain: "other", IP: first.IP}, {Domain: "inactive.example", IP: "10.0.0.0"}} {
		result, err := f.DeleteEntry(t.Context(), entry)
		if err != nil || result.Removed != 0 {
			t.Fatalf("stale delete: %+v %v", result, err)
		}
	}
	// Schedule a deferred touch before deleting: flushing it must not resurrect a row.
	v4.touchDomain(first.Domain, time.Now(), 0)
	for _, entry := range []contractresolver.FakeIPEntry{first, {Domain: first.Domain, IP: v6IP.String()}} {
		result, err := f.DeleteEntry(t.Context(), entry)
		if err != nil || result.Removed != 1 {
			t.Fatalf("delete: %+v %v", result, err)
		}
		result, err = f.DeleteEntry(t.Context(), entry)
		if err != nil || result.Removed != 0 {
			t.Fatalf("repeat delete: %+v %v", result, err)
		}
	}
	if err := v4.flushTouches(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, ok := v4.GetDomainFromIP(netip.MustParseAddr(first.IP)); ok {
		t.Fatal("deleted IPv4 reverse lookup remains")
	}
	if _, ok := v6.GetDomainFromIP(v6IP); ok {
		t.Fatal("deleted IPv6 reverse lookup remains")
	}
	items, total, err = f.ListEntries(t.Context(), 1, 25, first.Domain)
	if err != nil || total != 0 || len(items) != 0 {
		t.Fatalf("deleted entries: %v %d %v", items, total, err)
	}
	ip := v4.GetFakeIPForDomain(first.Domain)
	if !ip.IsValid() {
		t.Fatal("failed to reallocate deleted domain")
	}
	if domain, ok := v4.GetDomainFromIP(ip); !ok || domain != first.Domain {
		t.Fatalf("reallocated reverse lookup: %s %v", domain, ok)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := f.ListEntries(ctx, 1, 25, ""); err == nil {
		t.Fatal("canceled query accepted")
	}
	if _, err := f.DeleteEntry(ctx, first); err == nil {
		t.Fatal("canceled deletion accepted")
	}
}
