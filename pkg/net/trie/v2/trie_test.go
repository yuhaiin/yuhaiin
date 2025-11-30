package trie

import (
	crand "crypto/rand"
	"net"
	"strconv"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestTrie(t *testing.T) {
	trie := NewTrie[string]()

	// Insert rules
	trie.Insert("google.com", "google")
	trie.Insert("1.1.1.0/24", "cloudflare")
	trie.Insert("8.8.8.8", "google-dns")

	// Search for domain
	addrDomain, _ := netapi.ParseAddressPort("tcp", "www.google.com", 80)
	resDomain := trie.SearchFqdn(addrDomain)
	if !resDomain.Has("google") || resDomain.Len() != 1 {
		t.Errorf("expected to find 'google', got %v", resDomain)
	}

	// Search for CIDR
	addrCidr, _ := netapi.ParseAddressPort("tcp", "1.1.1.100", 80)
	resCidr := trie.SearchFqdn(addrCidr)
	if !resCidr.Has("cloudflare") || resCidr.Len() != 1 {
		t.Errorf("expected to find 'cloudflare', got %v", resCidr)
	}

	// Search for IP
	addrIp, _ := netapi.ParseAddressPort("tcp", "8.8.8.8", 53)
	resIp := trie.SearchFqdn(addrIp)
	if !resIp.Has("google-dns") || resIp.Len() != 1 {
		t.Errorf("expected to find 'google-dns', got %v", resIp)
	}

	// Test miss
	addrMiss, _ := netapi.ParseAddressPort("tcp", "example.com", 80)
	resMiss := trie.SearchFqdn(addrMiss)
	if resMiss.Len() != 0 {
		t.Errorf("expected no match, got %v", resMiss)
	}

	// Remove a rule
	trie.Remove("1.1.1.0/24", "cloudflare")
	resCidrAfterRemove := trie.SearchFqdn(addrCidr)
	if resCidrAfterRemove.Len() != 0 {
		t.Errorf("expected no match after remove, got %v", resCidrAfterRemove)
	}

	// Verify other rules still exist
	resDomainAfterRemove := trie.SearchFqdn(addrDomain)
	if !resDomainAfterRemove.Has("google") || resDomainAfterRemove.Len() != 1 {
		t.Errorf("domain rule should still exist, got %v", resDomainAfterRemove)
	}
}

func BenchmarkTrie(b *testing.B) {
	rules := []string{"google.com", "1.1.1.0/24", "facebook.com", "8.8.8.8", "github.com", "2.2.2.0/24"}

	addrs := make([]netapi.Address, 0)
	addr1, _ := netapi.ParseAddressPort("tcp", "www.google.com", 80)
	addrs = append(addrs, addr1)
	addr2, _ := netapi.ParseAddressPort("tcp", "1.1.1.100", 80)
	addrs = append(addrs, addr2)
	addr3, _ := netapi.ParseAddressPort("tcp", "login.facebook.com", 443)
	addrs = append(addrs, addr3)
	addr4, _ := netapi.ParseAddressPort("tcp", "8.8.8.8", 53)
	addrs = append(addrs, addr4)
	addr5, _ := netapi.ParseAddressPort("tcp", "gist.github.com", 443)
	addrs = append(addrs, addr5)
	addr6, _ := netapi.ParseAddressPort("tcp", "2.2.2.2", 80)
	addrs = append(addrs, addr6)

	// Add IPv6 addresses to the addrs slice for SearchFqdn
	for i := 0; i < 6; i++ { // Adding 6 IPv6 addresses
		var ipBytes [16]byte
		_, err := crand.Read(ipBytes[:])
		if err != nil {
			b.Fatal(err)
		}
		addr := net.IP(ipBytes[:])
		netapiAddr, _ := netapi.ParseAddressPort("tcp", addr.String(), 80)
		addrs = append(addrs, netapiAddr)
		// Also insert these IPv6 addresses into the trie for successful searches
		rules = append(rules, addr.String()) // Add to rules to ensure they are inserted in pre-fill
	}

	b.Run("Insert", func(b *testing.B) {
		trie := NewTrie[string]()
		b.ResetTimer()
		for i := 0; b.Loop(); i++ {
			trie.Insert(rules[i%len(rules)], "benchmark")
		}
	})

	b.Run("Search", func(b *testing.B) {
		trie := NewTrie[string]()
		for _, r := range rules {
			trie.Insert(r, "benchmark")
		}
		// add more rules for better distribution in benchmark
		for i := range 100 {
			trie.Insert("domain"+strconv.Itoa(i)+".com", "benchmark")
		}
		b.ResetTimer()
		for i := 0; b.Loop(); i++ {
			trie.SearchFqdn(addrs[i%len(addrs)])
		}
	})
}
