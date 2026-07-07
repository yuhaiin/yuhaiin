package fakeip

import (
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/cache/pebble"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func newTestSQLiteFakeIPPool(tb testing.TB, prefix netip.Prefix, maxNum int) (*SQLiteFakeIPPool, *sql.DB) {
	tb.Helper()

	store, err := storagesqlite.Open(context.Background(), filepath.Join(tb.TempDir(), "state.db"))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = store.Close() })

	pool, err := newSQLiteFakeIPPool(store.DB(), prefix, maxNum)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = pool.Close() })
	return pool, store.DB()
}

func TestSQLiteFakeIPPool(t *testing.T) {
	pool, _ := newTestSQLiteFakeIPPool(t, netip.MustParsePrefix("10.0.0.0/30"), 500)

	tests := []struct {
		domain string
		want   netip.Addr
	}{
		{"google.com", netip.MustParseAddr("10.0.0.0")},
		{"youtube.com", netip.MustParseAddr("10.0.0.1")},
		{"facebook.com", netip.MustParseAddr("10.0.0.2")},
		{"twitter.com", netip.MustParseAddr("10.0.0.3")},
	}

	for _, tt := range tests {
		got := pool.GetFakeIPForDomain(tt.domain)
		if got != tt.want {
			t.Errorf("GetFakeIPForDomain(%q) = %v, want %v", tt.domain, got, tt.want)
		}
	}

	got := pool.GetFakeIPForDomain("google.com")
	if got != netip.MustParseAddr("10.0.0.0") {
		t.Errorf("GetFakeIPForDomain(\"google.com\") = %v, want 10.0.0.0", got)
	}

	domain, ok := pool.GetDomainFromIP(netip.MustParseAddr("10.0.0.1"))
	if !ok || domain != "youtube.com" {
		t.Errorf("GetDomainFromIP(10.0.0.1) = %q, %v; want youtube.com, true", domain, ok)
	}
}

func TestSQLiteFakeIPPoolLRUEviction(t *testing.T) {
	pool, db := newTestSQLiteFakeIPPool(t, netip.MustParsePrefix("10.0.0.0/24"), 2)

	ipA := pool.GetFakeIPForDomain("a.com")
	ipB := pool.GetFakeIPForDomain("b.com")
	if ipA.String() != "10.0.0.0" || ipB.String() != "10.0.0.1" {
		t.Fatalf("unexpected initial allocation a=%s b=%s", ipA, ipB)
	}

	if _, err := db.ExecContext(context.Background(), `
		UPDATE fakeip_entries
		SET last_used_at = CASE domain
			WHEN 'a.com' THEN 300
			WHEN 'b.com' THEN 100
			ELSE last_used_at
		END
		WHERE domain IN ('a.com', 'b.com')
	`); err != nil {
		t.Fatal(err)
	}

	ipC := pool.GetFakeIPForDomain("c.com")
	if ipC != ipB {
		t.Fatalf("expected c.com to reuse least recently used %s, got %s", ipB, ipC)
	}
	if domain, ok := pool.GetDomainFromIP(ipB); !ok || domain != "c.com" {
		t.Fatalf("expected %s to map to c.com, got %q ok=%v", ipB, domain, ok)
	}
	if ip := pool.GetFakeIPForDomain("a.com"); ip != ipA {
		t.Fatalf("expected a.com to keep %s, got %s", ipA, ip)
	}
}

func TestSQLiteFakeIPPoolLazyTouch(t *testing.T) {
	pool, db := newTestSQLiteFakeIPPool(t, netip.MustParsePrefix("10.0.0.0/24"), 100)

	ip := pool.GetFakeIPForDomain("a.com")
	first := sqliteFakeIPLastUsed(t, db, "a.com")

	if got := pool.GetFakeIPForDomain("a.com"); got != ip {
		t.Fatalf("expected cached %s, got %s", ip, got)
	}
	if got := sqliteFakeIPLastUsed(t, db, "a.com"); got != first {
		t.Fatalf("recent domain hit updated last_used_at: got %d, want %d", got, first)
	}

	if _, ok := pool.GetDomainFromIP(ip); !ok {
		t.Fatalf("expected reverse hit for %s", ip)
	}
	if got := sqliteFakeIPLastUsed(t, db, "a.com"); got != first {
		t.Fatalf("recent reverse hit updated last_used_at: got %d, want %d", got, first)
	}

	stale := first - sqliteFakeIPTouchInterval.Nanoseconds() - 1
	if _, err := db.ExecContext(context.Background(), `
		UPDATE fakeip_entries
		SET last_used_at = ?
		WHERE domain = 'a.com'
	`, stale); err != nil {
		t.Fatal(err)
	}

	if got := pool.GetFakeIPForDomain("a.com"); got != ip {
		t.Fatalf("expected cached %s after stale touch, got %s", ip, got)
	}
	if err := pool.flushTouches(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := sqliteFakeIPLastUsed(t, db, "a.com"); got <= stale {
		t.Fatalf("stale domain hit did not update last_used_at: got %d, stale %d", got, stale)
	}
}

func TestSQLiteFakeIPPoolPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := storagesqlite.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	prefix := netip.MustParsePrefix("192.168.1.0/24")
	pool1, err := newSQLiteFakeIPPool(store.DB(), prefix, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pool1.Close() }()
	pool1.GetFakeIPForDomain("d1")
	pool1.GetFakeIPForDomain("d2")
	pool1.GetFakeIPForDomain("d3")

	pool2, err := newSQLiteFakeIPPool(store.DB(), prefix, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pool2.Close() }()
	ip := pool2.GetFakeIPForDomain("d4")
	if ip.String() != "192.168.1.3" {
		t.Fatalf("expected persisted cursor to allocate 192.168.1.3, got %s", ip)
	}
}

func TestSQLiteFakeIPPoolImportsLegacyPrefixBucket(t *testing.T) {
	legacy, err := pebble.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = legacy.Close() })

	prefix := netip.MustParsePrefix("10.8.0.0/24")
	legacyBucket := legacy.NewCache(prefix.String())
	legacyIP := netip.MustParseAddr("10.8.0.2")
	shortDomainIP := netip.MustParseAddr("10.8.0.8")
	legacyCursor := netip.MustParseAddr("10.8.0.3")
	if err := legacyBucket.Put([]byte("legacy.example"), legacyIP.AsSlice()); err != nil {
		t.Fatal(err)
	}
	if err := legacyBucket.Put(legacyIP.AsSlice(), []byte("legacy.example")); err != nil {
		t.Fatal(err)
	}
	if err := legacyBucket.Put([]byte("abcd"), shortDomainIP.AsSlice()); err != nil {
		t.Fatal(err)
	}
	if err := legacyBucket.Put([]byte(cursorKey), legacyCursorValue(4, legacyCursor)); err != nil {
		t.Fatal(err)
	}

	store, err := storagesqlite.Open(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	pool, err := newSQLiteFakeIPPool(store.DB(), prefix, 100, legacy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pool.Close() })

	if got := pool.GetFakeIPForDomain("legacy.example"); got != legacyIP {
		t.Fatalf("expected legacy.example to keep %s, got %s", legacyIP, got)
	}
	if domain, ok := pool.GetDomainFromIP(legacyIP); !ok || domain != "legacy.example" {
		t.Fatalf("expected reverse legacy mapping, got domain=%q ok=%v", domain, ok)
	}
	if got := pool.GetFakeIPForDomain("abcd"); got != shortDomainIP {
		t.Fatalf("expected short legacy domain to keep %s, got %s", shortDomainIP, got)
	}
	if got := pool.GetFakeIPForDomain("new.example"); got != netip.MustParseAddr("10.8.0.4") {
		t.Fatalf("expected cursor import to allocate 10.8.0.4, got %s", got)
	}
}

func TestSQLiteFakeIPPoolImportsLegacyLRUBucket(t *testing.T) {
	legacy, err := pebble.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = legacy.Close() })

	prefix := netip.MustParsePrefix("10.9.0.0/24")
	legacyBucket := legacy.NewCache("fakedns_cache")
	legacyIP := netip.MustParseAddr("10.9.0.7")
	if err := legacyBucket.Put([]byte("old-lru.example"), legacyIP.AsSlice()); err != nil {
		t.Fatal(err)
	}
	if err := legacyBucket.Put(legacyIP.AsSlice(), []byte("old-lru.example")); err != nil {
		t.Fatal(err)
	}

	store, err := storagesqlite.Open(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	pool, err := newSQLiteFakeIPPool(store.DB(), prefix, 100, legacy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pool.Close() })

	if got := pool.GetFakeIPForDomain("old-lru.example"); got != legacyIP {
		t.Fatalf("expected old-lru.example to keep %s, got %s", legacyIP, got)
	}
}

func sqliteFakeIPLastUsed(tb testing.TB, db *sql.DB, domain string) int64 {
	tb.Helper()
	var lastUsedAt int64
	if err := db.QueryRowContext(context.Background(), `
		SELECT last_used_at
		FROM fakeip_entries
		WHERE domain = ?
	`, domain).Scan(&lastUsedAt); err != nil {
		tb.Fatal(err)
	}
	return lastUsedAt
}

func legacyCursorValue(index uint64, addr netip.Addr) []byte {
	buf := make([]byte, 8+len(addr.AsSlice()))
	binary.BigEndian.PutUint64(buf[:8], index)
	copy(buf[8:], addr.AsSlice())
	return buf
}

func BenchmarkSQLiteFakeIPPool(b *testing.B) {
	const seededDomains = 4096
	prefix := netip.MustParsePrefix("10.0.0.0/8")

	b.Run("sqlite/new_domains", func(b *testing.B) {
		pool, _ := newTestSQLiteFakeIPPool(b, prefix, 65535)
		b.ReportAllocs()
		for i := 0; b.Loop(); i++ {
			pool.GetFakeIPForDomain(fmt.Sprintf("domain%d.com", i))
		}
	})

	b.Run("sqlite/hits", func(b *testing.B) {
		pool, _ := newTestSQLiteFakeIPPool(b, prefix, 65535)
		for i := range seededDomains {
			pool.GetFakeIPForDomain(fmt.Sprintf("domain%d.com", i))
		}
		b.ReportAllocs()
		for i := 0; b.Loop(); i++ {
			pool.GetFakeIPForDomain(fmt.Sprintf("domain%d.com", i%seededDomains))
		}
	})
}
