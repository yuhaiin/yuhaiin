package fakeip

import (
	"fmt"
	"net/netip"
	"os"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/cache/pebble"
)

func newTestCache() *pebble.Cache {
	nd, err := pebble.New("test.db")
	if err != nil {
		panic(err)
	}
	return nd
}

func TestDiskFakeIPPool(t *testing.T) {
	pool := NewDiskFakeIPPool(netip.MustParsePrefix("10.0.0.0/30"), newTestCache(), 500)
	defer t.Cleanup(func() {
		_ = os.RemoveAll("test.db")
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
		_ = os.RemoveAll("test.db")
	})

	// 10.0.0.0/30 -> 4 IPs: .0, .1, .2, .3
	pool := NewDiskFakeIPPool(netip.MustParsePrefix("10.0.0.0/30"), newTestCache(), 10)

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
	nd := newTestCache()
	defer nd.Close()

	pool := NewDiskFakeIPPool(netip.MustParsePrefix("10.0.0.0/8"), nd, 500)

	for i := 0; b.Loop(); i++ {
		pool.GetFakeIPForDomain(fmt.Sprintf("domain%d.com", i))
	}
}

func NewMemCache() *pebble.Cache {
	return newTestCache()
}

// --- Main Test Suite ---

func TestDiskFakeIPPool2(t *testing.T) {
	t.Run("BasicAllocationAndCacheHit", func(t *testing.T) {
		// Setup: 10.0.0.0/24, MaxNum 100
		prefix := netip.MustParsePrefix("10.0.0.0/24")
		db := NewMemCache()
		t.Cleanup(func() { os.RemoveAll("test.db") })
		pool := NewDiskFakeIPPool(prefix, db, 100)

		// 1. First Domain -> 10.0.0.0
		ipA := pool.GetFakeIPForDomain("a.com")
		if ipA.String() != "10.0.0.0" {
			t.Fatalf("Expected 10.0.0.0, got %s", ipA)
		}

		// 2. Cache Hit -> Should return 10.0.0.0 again (no increment)
		ipA2 := pool.GetFakeIPForDomain("a.com")
		if ipA2 != ipA {
			t.Errorf("Cache hit failed. Expected %s, got %s", ipA, ipA2)
		}

		// 3. Second Domain -> 10.0.0.1
		ipB := pool.GetFakeIPForDomain("b.com")
		if ipB.String() != "10.0.0.1" {
			t.Fatalf("Expected 10.0.0.1, got %s", ipB)
		}
	})

	t.Run("MaxNumOverflowAndEviction", func(t *testing.T) {
		// Setup: MaxNum = 2. Subnet is large (/24), but we restrict to 2 IPs.
		prefix := netip.MustParsePrefix("10.0.0.0/24")
		db := NewMemCache()
		t.Cleanup(func() { os.RemoveAll("test.db") })
		pool := NewDiskFakeIPPool(prefix, db, 2)

		// Fill the pool
		pool.GetFakeIPForDomain("1.com") // 10.0.0.0
		pool.GetFakeIPForDomain("2.com") // 10.0.0.1

		// 3rd Domain -> Should Overflow to 10.0.0.0 (Index 1)
		// This must EVICT "1.com"
		ip3 := pool.GetFakeIPForDomain("3.com")
		if ip3.String() != "10.0.0.0" {
			t.Fatalf("Expected wrap around to 10.0.0.0, got %s", ip3)
		}

		// Check Eviction: 1.com should no longer resolve to 10.0.0.0
		// Because 10.0.0.0 is now owned by 3.com
		domain, ok := pool.GetDomainFromIP(ip3)
		if !ok || domain != "3.com" {
			t.Errorf("IP 10.0.0.0 should map to 3.com, got %s", domain)
		}

		// Re-requesting 1.com should generate a NEW allocation
		// Next available slot is 10.0.0.1 (Index 2), currently owned by 2.com.
		// It will steal 10.0.0.1.
		ip1New := pool.GetFakeIPForDomain("1.com")
		if ip1New.String() != "10.0.0.1" {
			t.Errorf("Expected evicted domain 1.com to take next slot 10.0.0.1, got %s", ip1New)
		}
	})

	t.Run("SubnetSmallerThanMaxNum", func(t *testing.T) {
		// Setup: /30 subnet (4 IPs: .0, .1, .2, .3)
		// MaxNum is 100, which is physically impossible for this subnet.
		// Logic should auto-cap MaxNum to 4.
		prefix := netip.MustParsePrefix("10.0.0.0/30")
		db := NewMemCache()
		t.Cleanup(func() { os.RemoveAll("test.db") })
		pool := NewDiskFakeIPPool(prefix, db, 100)

		if pool.maxNum != 4 {
			t.Errorf("Expected maxNum to be capped at 4, got %d", pool.maxNum)
		}

		// Allocate 4 IPs
		pool.GetFakeIPForDomain("a") // .0
		pool.GetFakeIPForDomain("b") // .1
		pool.GetFakeIPForDomain("c") // .2
		pool.GetFakeIPForDomain("d") // .3

		// 5th Allocation -> Must wrap to .0
		ip := pool.GetFakeIPForDomain("e")
		if ip.String() != "10.0.0.0" {
			t.Errorf("Expected wrap to 10.0.0.0 due to subnet size, got %s", ip)
		}
	})

	t.Run("IPv6LargeSubnetLimit", func(t *testing.T) {
		// Setup: IPv6 /64 (Huge). MaxNum 5.
		// Tests that we don't try to iterate the whole subnet.
		prefix := netip.MustParsePrefix("fd00::/64")
		db := NewMemCache()
		t.Cleanup(func() { os.RemoveAll("test.db") })
		pool := NewDiskFakeIPPool(prefix, db, 5)

		for i := 0; i < 5; i++ {
			pool.GetFakeIPForDomain(fmt.Sprintf("%d.com", i))
		}

		// Check current cursor
		if pool.current.String() != "fd00::4" {
			t.Errorf("Expected cursor at fd00::4, got %s", pool.current)
		}

		// 6th item -> Wrap to fd00::
		ip := pool.GetFakeIPForDomain("overflow.com")
		if ip.String() != "fd00::" {
			t.Errorf("Expected wrap to fd00::, got %s", ip)
		}
	})

	t.Run("Persistence", func(t *testing.T) {
		prefix := netip.MustParsePrefix("192.168.1.0/24")
		db := NewMemCache() // Shared DB
		t.Cleanup(func() { os.RemoveAll("test.db") })

		// --- Instance 1 ---
		pool1 := NewDiskFakeIPPool(prefix, db, 100)
		pool1.GetFakeIPForDomain("d1") // .0
		pool1.GetFakeIPForDomain("d2") // .1
		pool1.GetFakeIPForDomain("d3") // .2

		// Verify DB state
		cursorVal, _ := db.NewCache(prefix.String()).Get([]byte("reserved_cursor_state"))
		if cursorVal == nil {
			t.Fatal("Cursor not saved to DB")
		}

		// --- Instance 2 (Restart) ---
		pool2 := NewDiskFakeIPPool(prefix, db, 100)

		// pool2 should load cursor from DB (.2)
		// Next allocation should be .3
		ip := pool2.GetFakeIPForDomain("d4")
		if ip.String() != "192.168.1.3" {
			t.Errorf("Persistence failed. Expected 192.168.1.3, got %s", ip)
		}
	})

	t.Run("ConsistencyWithEviction", func(t *testing.T) {
		// This tests the data consistency when multiple domains force rapid overwrites
		prefix := netip.MustParsePrefix("10.0.0.0/24")
		db := NewMemCache()
		t.Cleanup(func() { os.RemoveAll("test.db") })
		pool := NewDiskFakeIPPool(prefix, db, 2) // Small pool: [IP0, IP1]

		// 1. A -> IP0
		pool.GetFakeIPForDomain("A")
		// 2. B -> IP1
		pool.GetFakeIPForDomain("B")

		// 3. C -> IP0 (Evicts A)
		pool.GetFakeIPForDomain("C")

		// 4. Verify A is gone
		if _, ok := pool.getIP("A"); ok {
			t.Errorf("A should be evicted from cache")
		}
		// Verify IP0 maps to C
		ip0 := netip.MustParseAddr("10.0.0.0")
		if d, _ := pool.GetDomainFromIP(ip0); d != "C" {
			t.Errorf("IP0 should map to C")
		}

		// 5. A comes back -> IP1 (Evicts B)
		ipNewA := pool.GetFakeIPForDomain("A")
		if ipNewA.String() != "10.0.0.1" {
			t.Errorf("A should get next available IP (IP1), got %s", ipNewA)
		}

		// 6. Verify B is gone
		if _, ok := pool.getIP("B"); ok {
			t.Errorf("B should be evicted from cache")
		}

		// 7. Verify C is still valid at IP0
		if d, _ := pool.GetDomainFromIP(ip0); d != "C" {
			t.Errorf("IP0 should still map to C")
		}
	})
}
