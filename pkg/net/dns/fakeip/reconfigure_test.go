package fakeip

import (
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestFakeDNSReconfigurePreservesUnchangedFamilyLease(t *testing.T) {
	for _, unchangedFamily := range []string{"IPv4", "IPv6"} {
		t.Run(unchangedFamily, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.db")
			prefix4 := netip.MustParsePrefix("198.18.0.1/32")
			prefix6 := netip.MustParsePrefix("2001:2::1/128")
			f, err := NewFakeDNS(nil, prefix4, prefix6, path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = f.Close() })
			preserved := f.ipv4
			if unchangedFamily == "IPv4" {
				prefix6 = netip.MustParsePrefix("2001:2::2/128")
			} else {
				preserved = f.ipv6
				prefix4 = netip.MustParsePrefix("198.18.0.2/32")
			}
			ip := preserved.GetFakeIPForDomain("active.example")
			_, release, ok := preserved.LeaseDomainFromIP(ip)
			if !ok {
				t.Fatal("failed to acquire mapping lease")
			}
			t.Cleanup(release)
			if err := f.Reconfigure(prefix4, prefix6, path); err != nil {
				t.Fatal(err)
			}
			current := f.ipv4
			if unchangedFamily == "IPv6" {
				current = f.ipv6
			}
			if current != preserved {
				t.Fatal("unchanged family's lease owner was replaced")
			}
			p := current.(*SQLiteFakeIPPool)
			if _, err := p.db.ExecContext(t.Context(), `UPDATE fakeip_entries SET last_used_at = ? WHERE family = ? AND prefix = ?`, time.Now().Add(-2*time.Hour).UnixNano(), p.family, p.key); err != nil {
				t.Fatal(err)
			}
			if got := current.GetFakeIPForDomain("other.example"); got.IsValid() {
				t.Fatalf("reconfigured pool reused active address %s as %s", ip, got)
			}
		})
	}
}

func TestFakeDNSReconfigureOpenFailurePreservesPools(t *testing.T) {
	f, err := NewFakeDNS(nil, netip.MustParsePrefix("198.18.0.1/32"), netip.MustParsePrefix("2001:2::1/128"), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	original4, original6 := f.ipv4, f.ipv6
	ip := original4.GetFakeIPForDomain("original.example")
	if err := f.Reconfigure(netip.MustParsePrefix("198.18.0.2/32"), netip.MustParsePrefix("2001:2::2/128"), t.TempDir()); err == nil {
		t.Fatal("opening a directory as the new database unexpectedly succeeded")
	}
	if f.ipv4 != original4 || f.ipv6 != original6 {
		t.Fatal("failed reconfiguration replaced an existing pool")
	}
	if domain, ok := f.GetDomainFromIP(ip); !ok || domain != "original.example" {
		t.Fatalf("failed reconfiguration damaged existing mapping: %q, %v", domain, ok)
	}
}
