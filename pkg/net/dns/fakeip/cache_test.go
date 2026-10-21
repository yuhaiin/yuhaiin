package fakeip

import (
	"context"
	"fmt"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
)

func TestFakeIPCacheHitsDoNotQuerySQLite(t *testing.T) {
	p, _ := newTestSQLiteFakeIPPool(t, netip.MustParsePrefix("198.18.0.0/16"), 100)
	ip := p.GetFakeIPForDomain("cached.example")
	if err := p.lookupDomainStmt.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.lookupIPStmt.Close(); err != nil {
		t.Fatal(err)
	}
	if got := p.GetFakeIPForDomain("cached.example"); got != ip {
		t.Fatalf("cached domain requires SQL: %v", got)
	}
	if domain, ok := p.GetDomainFromIP(ip); !ok || domain != "cached.example" {
		t.Fatalf("cached reverse lookup requires SQL: %q, %v", domain, ok)
	}
	if domain, release, ok := p.LeaseDomainFromIP(ip); !ok || domain != "cached.example" {
		t.Fatalf("cached lease requires SQL: %q, %v", domain, ok)
	} else {
		release()
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if len(p.cache.entries) != 0 {
		t.Fatal("last pool close retained cache storage")
	}
	if p.GetFakeIPForDomain("cached.example").IsValid() {
		t.Fatal("closed pool still serves cached domains")
	}
	if _, ok := p.GetDomainFromIP(ip); ok {
		t.Fatal("closed pool still serves cached IPs")
	}
}

func TestFakeIPCacheBoundsAndLeaseSurvivesReplacement(t *testing.T) {
	p, db := newTestSQLiteFakeIPPool(t, netip.MustParsePrefix("198.18.0.0/16"), fakeIPCacheCapacity+1)
	ip := p.GetFakeIPForDomain("leased.example")
	_, release, ok := p.LeaseDomainFromIP(ip)
	if !ok {
		t.Fatal("cannot acquire lease")
	}
	defer release()
	for i := range fakeIPCacheCapacity {
		if got := p.GetFakeIPForDomain(fmt.Sprintf("cache-%d.example", i)); !got.IsValid() {
			t.Fatal("cannot fill cache")
		}
	}
	if len(p.cache.domains) != fakeIPCacheCapacity || len(p.cache.ips) != fakeIPCacheCapacity {
		t.Fatalf("unbounded cache: %d/%d", len(p.cache.domains), len(p.cache.ips))
	}
	if _, ok := p.cache.ips[ip]; ok {
		t.Fatal("oldest slot was not replaced")
	}
	if _, err := db.ExecContext(t.Context(), `UPDATE fakeip_entries SET last_used_at = ?`, time.Now().Add(-2*time.Hour).UnixNano()); err != nil {
		t.Fatal(err)
	}
	if got := p.GetFakeIPForDomain("replacement.example"); !got.IsValid() || got == ip {
		t.Fatalf("cache replacement lost lease protection: %v", got)
	}
	if domain, ok := p.GetDomainFromIP(ip); !ok || domain != "leased.example" {
		t.Fatalf("cache replacement lost durable identity: %q, %v", domain, ok)
	}
}

func TestFakeIPCacheSharedHandlesAndDeletion(t *testing.T) {
	first, db := newTestSQLiteFakeIPPool(t, netip.MustParsePrefix("198.18.0.1/32"), 1)
	second, err := newSQLiteFakeIPPool(db, first.prefix, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	f := &FakeDNS{ipv4: first}
	ip := first.GetFakeIPForDomain("first.example")
	if got := second.GetFakeIPForDomain("first.example"); got != ip {
		t.Fatal("second handle cannot read mapping")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	entry := contract.FakeIPEntry{Domain: "first.example", IP: ip.String()}
	if _, err := f.DeleteEntry(ctx, entry); err == nil {
		t.Fatal("canceled deletion succeeded")
	}
	if got := second.GetFakeIPForDomain("first.example"); got != ip {
		t.Fatal("failed deletion invalidated identity")
	}
	if response, err := f.DeleteEntry(t.Context(), entry); err != nil || response.Removed != 1 {
		t.Fatalf("delete = %+v, %v", response, err)
	}
	if _, ok := second.GetDomainFromIP(ip); ok {
		t.Fatal("second handle retained deleted cached mapping")
	}
	if got := second.GetFakeIPForDomain("second.example"); got != ip {
		t.Fatalf("management deletion did not restore pool capacity: %v", got)
	}
	_, release, ok := first.LeaseDomainFromIP(ip)
	if !ok {
		t.Fatal("cannot lease replacement through first handle")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `UPDATE fakeip_entries SET last_used_at = ?`, time.Now().Add(-2*time.Hour).UnixNano()); err != nil {
		t.Fatal(err)
	}
	if got := second.GetFakeIPForDomain("third.example"); got.IsValid() {
		t.Fatal("closing one handle discarded another handle's active lease")
	}
	release()
	if got := second.GetFakeIPForDomain("third.example"); got.IsValid() {
		t.Fatal("closed handle's lease release lost its final touch")
	}
}

func TestFakeIPCacheAllocationRollbackDoesNotPublish(t *testing.T) {
	p, db := newTestSQLiteFakeIPPool(t, netip.MustParsePrefix("198.18.0.1/32"), 1)
	ip := p.GetFakeIPForDomain("original.example")
	if _, err := db.ExecContext(t.Context(), `UPDATE fakeip_entries SET last_used_at = ?`, time.Now().Add(-2*time.Hour).UnixNano()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `CREATE TRIGGER reject_fakeip BEFORE INSERT ON fakeip_entries BEGIN SELECT RAISE(ABORT, 'allocation failed'); END`); err != nil {
		t.Fatal(err)
	}
	if got := p.GetFakeIPForDomain("replacement.example"); got.IsValid() {
		t.Fatal("failed transaction published a mapping")
	}
	if domain, ok := p.GetDomainFromIP(ip); !ok || domain != "original.example" {
		t.Fatalf("rollback lost original mapping: %q, %v", domain, ok)
	}
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if count, err := p.entryCount(t.Context(), tx); err != nil || count != 1 {
		t.Fatalf("rolled back count = %d, %v", count, err)
	}
}

func TestFakeIPCachedTouchProtectsReuseAndDoesNotSlide(t *testing.T) {
	p, db := newTestSQLiteFakeIPPool(t, netip.MustParsePrefix("198.18.0.1/32"), 1)
	ip := p.GetFakeIPForDomain("active.example")
	stale := time.Now().Add(-2 * time.Hour).UnixNano()
	if _, err := db.ExecContext(t.Context(), `UPDATE fakeip_entries SET last_used_at = ?`, stale); err != nil {
		t.Fatal(err)
	}
	p.cache.entries[p.cache.ips[ip]].lastTouch.Store(stale)
	if got := p.GetFakeIPForDomain("active.example"); got != ip {
		t.Fatal("cache miss")
	}
	if got := p.GetFakeIPForDomain("other.example"); got.IsValid() {
		t.Fatal("recent cached activity was not flushed before eviction")
	}
	// A cold read within the batching interval must retain the persisted time,
	// rather than delay the next touch by a fresh interval on every cache load.
	recent := time.Now().Add(-4 * time.Minute).UnixNano()
	if _, err := db.ExecContext(t.Context(), `UPDATE fakeip_entries SET last_used_at = ?`, recent); err != nil {
		t.Fatal(err)
	}
	p.cache.removeDomain("active.example")
	if got := p.GetFakeIPForDomain("active.example"); got != ip {
		t.Fatal("cannot reload mapping")
	}
	if got := p.cache.entries[p.cache.ips[ip]].lastTouch.Load(); got != recent {
		t.Fatalf("cold read moved the persisted touch boundary: %d != %d", got, recent)
	}
}

func TestFakeIPCacheOversizedDomainInvalidatesReusedIP(t *testing.T) {
	c := newFakeIPCache(2)
	ip := netip.MustParseAddr("198.18.0.1")
	c.put("old.example", ip, 1)
	c.put(strings.Repeat("x", 254), ip, 2)
	if len(c.domains) != 0 || len(c.ips) != 0 {
		t.Fatal("uncached replacement retained old identity")
	}
}

func TestFakeIPCacheSharedHandleTouchProtectsReuse(t *testing.T) {
	first, db := newTestSQLiteFakeIPPool(t, netip.MustParsePrefix("198.18.0.1/32"), 1)
	second, err := newSQLiteFakeIPPool(db, first.prefix, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	ip := first.GetFakeIPForDomain("recent.example")
	stale := time.Now().Add(-2 * time.Hour).UnixNano()
	if _, err := db.ExecContext(t.Context(), `UPDATE fakeip_entries SET last_used_at = ?`, stale); err != nil {
		t.Fatal(err)
	}
	first.cache.entries[first.cache.ips[ip]].lastTouch.Store(stale)
	if domain, ok := first.GetDomainFromIP(ip); !ok || domain != "recent.example" {
		t.Fatal("cannot touch shared cached mapping")
	}
	if got := second.GetFakeIPForDomain("other.example"); got.IsValid() {
		t.Fatal("second handle did not flush first handle's queued touch")
	}
}

func TestFakeIPCacheConcurrentReadsLeasesAndInvalidation(t *testing.T) {
	p, _ := newTestSQLiteFakeIPPool(t, netip.MustParsePrefix("198.18.0.0/16"), 64)
	// A small cache forces slot reuse while readers hold shared pool locks.
	p.state.cache = newFakeIPCache(8)
	ips := make([]netip.Addr, 16)
	for i := range ips {
		ips[i] = p.GetFakeIPForDomain(fmt.Sprintf("hot-%d.example", i))
	}
	var workers sync.WaitGroup
	for worker := range 4 {
		workers.Go(func() {
			for i := range 500 {
				index := (i + worker) % len(ips)
				domain := fmt.Sprintf("hot-%d.example", index)
				if got := p.GetFakeIPForDomain(domain); got != ips[index] {
					t.Errorf("concurrent domain mapping changed: %v", got)
					return
				}
				name, release, ok := p.LeaseDomainFromIP(ips[index])
				if !ok || name != domain {
					t.Errorf("concurrent lease mapping changed: %q", name)
					return
				}
				release()
			}
		})
	}
	workers.Go(func() {
		f := &FakeDNS{ipv4: p}
		for i := range 100 {
			domain := fmt.Sprintf("temporary-%d.example", i)
			ip := p.GetFakeIPForDomain(domain)
			if !ip.IsValid() {
				t.Error("temporary allocation failed")
				return
			}
			if _, err := f.DeleteEntry(t.Context(), contract.FakeIPEntry{Domain: domain, IP: ip.String()}); err != nil {
				t.Error(err)
				return
			}
		}
	})
	workers.Wait()
}

func BenchmarkFakeIPCacheMemory(b *testing.B) {
	for _, maximumDomain := range []bool{false, true} {
		b.Run(fmt.Sprintf("long_%t", maximumDomain), func(b *testing.B) {
			domains := make([]string, fakeIPCacheCapacity)
			for i := range domains {
				domains[i] = fmt.Sprintf("domain-%d.example", i)
				if maximumDomain {
					domains[i] = fmt.Sprintf("%06d.", i) + strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("a", 54)
				}
			}
			for b.Loop() {
				runtime.GC()
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				c := newFakeIPCache(fakeIPCacheCapacity)
				ip := netip.MustParseAddr("198.18.0.0")
				for _, domain := range domains {
					c.put(domain, ip, 1)
					ip = ip.Next()
				}
				runtime.GC()
				runtime.ReadMemStats(&after)
				b.ReportMetric(float64(after.HeapAlloc)-float64(before.HeapAlloc), "retained_bytes/pool")
				runtime.KeepAlive(c)
				runtime.KeepAlive(domains)
			}
		})
	}
}
