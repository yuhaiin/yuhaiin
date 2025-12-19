package fakeip

import (
	"fmt"
	"net/netip"
	"os"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	ybbolt "github.com/Asutorufa/yuhaiin/pkg/utils/cache/bbolt"
	"go.etcd.io/bbolt"
)

func newTestCache() cache.Cache {
	nd, _ := bbolt.Open("test.db", os.ModePerm, &bbolt.Options{})
	return ybbolt.NewCache(nd)
}

func TestDiskFakeIPPool(t *testing.T) {
	pool := NewDiskFakeIPPool(netip.MustParsePrefix("10.0.0.0/30"), newTestCache())
	defer t.Cleanup(func() {
		_ = os.Remove("test.db")
	})

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

	// Test re-getting existing domain
	got := pool.GetFakeIPForDomain("google.com")
	if got != netip.MustParseAddr("10.0.0.0") {
		t.Errorf("GetFakeIPForDomain(\"google.com\") = %v, want 10.0.0.0", got)
	}

	// Test reverse lookup
	domain, ok := pool.GetDomainFromIP(netip.MustParseAddr("10.0.0.1"))
	if !ok || domain != "youtube.com" {
		t.Errorf("GetDomainFromIP(10.0.0.1) = %q, %v; want youtube.com, true", domain, ok)
	}
}

func TestDiskFakeIPPool_Exhaustion(t *testing.T) {
	defer t.Cleanup(func() {
		_ = os.Remove("test.db")
	})

	// 10.0.0.0/30 -> 4 IPs: .0, .1, .2, .3
	pool := NewDiskFakeIPPool(netip.MustParsePrefix("10.0.0.0/30"), newTestCache())

	// Fill the pool
	for i := range 4 {
		domain := fmt.Sprintf("d%d.com", i)
		ip := pool.GetFakeIPForDomain(domain)
		expected := netip.MustParseAddr(fmt.Sprintf("10.0.0.%d", i))
		if ip != expected {
			t.Errorf("Fill: GetFakeIPForDomain(%q) = %v, want %v", domain, ip, expected)
		}
	}

	// Now pool is full. Next allocation should wrap around to .0
	domain := "overflow.com"
	ip := pool.GetFakeIPForDomain(domain)
	expected := netip.MustParseAddr("10.0.0.0")
	if ip != expected {
		t.Errorf("Overflow: GetFakeIPForDomain(%q) = %v, want %v", domain, ip, expected)
	}

	// Verify reverse lookup for 10.0.0.0 is now overflow.com
	d, ok := pool.GetDomainFromIP(expected)
	if !ok || d != "overflow.com" {
		t.Errorf("GetDomainFromIP(%v) = %q, %v; want overflow.com, true", expected, d, ok)
	}

// When the pool is exhausted, the next allocation for a new domain reuses an IP from the beginning of the range.
	// The old mapping for the reused IP is deleted. When we request an IP for the old domain (`d0.com`) again,
	// it will be treated as a new allocation and will also be allocated an IP from the beginning of the range, which happens to be the same IP.
	ipOld := pool.GetFakeIPForDomain("d0.com")
	if ipOld != expected {
		t.Errorf("GetFakeIPForDomain(\"d0.com\") = %v, want %v (collision accepted)", ipOld, expected)
	}
}

func BenchmarkDiskFakeIPPool(b *testing.B) {
	pool := NewDiskFakeIPPool(netip.MustParsePrefix("10.0.0.0/8"), newTestCache())

	for i := 0; b.Loop(); i++ {
		pool.GetFakeIPForDomain(fmt.Sprintf("domain%d.com", i))
	}
}
