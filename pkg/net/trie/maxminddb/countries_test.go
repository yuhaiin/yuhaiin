package maxminddb

import (
	"net/netip"
	"slices"
	"sync"
	"testing"
)

func TestCountriesUseMatchingFieldsAndDatabaseGeneration(t *testing.T) {
	first, err := NewMaxMindDB("testdata/countries.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	want := []string{"CN", "JP", "LAN"}
	codes, err := first.Countries()
	if err != nil || !slices.Equal(codes, want) {
		t.Fatalf("countries = %v, %v", codes, err)
	}
	for _, ip := range []string{"1.0.0.1", "1.0.1.1", "2001:4860::1", "10.0.0.1"} {
		code, err := first.Lookup(netip.MustParseAddr(ip))
		if err != nil || !slices.Contains(codes, code) {
			t.Fatalf("lookup %s = %q, %v", ip, code, err)
		}
	}
	codes[0] = "changed by caller"
	again, err := first.Countries()
	if err != nil || !slices.Equal(again, want) {
		t.Fatalf("cached countries mutated: %v, %v", again, err)
	}
	second, err := NewMaxMindDB("testdata/updated.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	updated, err := second.Countries()
	if err != nil || !slices.Equal(updated, []string{"US"}) {
		t.Fatalf("updated countries = %v, %v", updated, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Countries(); err == nil {
		t.Fatal("closed database returned countries")
	}
}

func TestCountriesConcurrentWithLookup(t *testing.T) {
	db, err := NewMaxMindDB("testdata/countries.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var workers sync.WaitGroup
	for range 20 {
		workers.Go(func() {
			codes, err := db.Countries()
			if err != nil || !slices.Equal(codes, []string{"CN", "JP", "LAN"}) {
				t.Errorf("countries = %v, %v", codes, err)
				return
			}
			codes[0] = "caller owned"
			code, err := db.Lookup(netip.MustParseAddr("1.0.0.1"))
			if err != nil || code != "CN" {
				t.Errorf("lookup = %q, %v", code, err)
			}
		})
	}
	workers.Wait()
}
