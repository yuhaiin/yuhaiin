package cidr

import (
	"net"
	"net/netip"
	"testing"
)

func TestTrieOverlappingPrefixesAndDefaults(t *testing.T) {
	trie := NewTrie[string]()
	// More-specific routes must survive a later parent or default route.
	trie.InsertCIDR(netip.MustParsePrefix("10.1.0.0/16"), "specific")
	trie.InsertCIDR(netip.MustParsePrefix("10.0.0.0/8"), "broad")
	trie.InsertCIDR(netip.MustParsePrefix("0.0.0.0/0"), "default")
	for _, tc := range []struct{ ip, want string }{
		{"10.1.2.3", "specific"},
		{"10.2.3.4", "broad"},
		{"8.8.8.8", "default"},
	} {
		got, ok := trie.SearchIP(net.ParseIP(tc.ip))
		if !ok || got != tc.want {
			t.Errorf("lookup %s: got %q, %v; want %q", tc.ip, got, ok, tc.want)
		}
	}
	trie.InsertCIDR(netip.MustParsePrefix("10.0.0.0/8"), "updated")
	if got, ok := trie.SearchIP(net.ParseIP("10.1.2.3")); !ok || got != "specific" {
		t.Fatalf("parent update erased child route: %q, %v", got, ok)
	}
	if got, ok := trie.SearchIP(net.ParseIP("10.2.3.4")); !ok || got != "updated" {
		t.Fatalf("parent update not applied: %q, %v", got, ok)
	}
}

func TestTrieIPv6DefaultAndSpecificRoute(t *testing.T) {
	trie := NewTrie[string]()
	trie.InsertCIDR(netip.MustParsePrefix("2001:db8::/32"), "specific")
	trie.InsertCIDR(netip.MustParsePrefix("::/0"), "default")
	for _, tc := range []struct{ ip, want string }{
		{"2001:db8::1", "specific"},
		{"2001:4860::8888", "default"},
	} {
		got, ok := trie.SearchIP(net.ParseIP(tc.ip))
		if !ok || got != tc.want {
			t.Errorf("lookup %s: got %q, %v; want %q", tc.ip, got, ok, tc.want)
		}
	}
}

func TestTrieInvalidIPDoesNotMatchDefault(t *testing.T) {
	c := NewTrie[string]()
	c.InsertCIDR(netip.MustParsePrefix("::/0"), "default")
	for _, ip := range []net.IP{nil, {}, {192, 0, 2}, make(net.IP, 15), make(net.IP, 17)} {
		if mark, ok := c.SearchIP(ip); ok {
			t.Errorf("invalid IP %x matched %q", []byte(ip), mark)
		}
	}
}

func TestTrieInvalidIPCannotInsertDefault(t *testing.T) {
	var trie Trie[string]
	trie.Insert(nil, 0, "invalid")
	if mark, ok := trie.Search(net.ParseIP("2001:db8::1")); ok {
		t.Fatalf("invalid insertion supplied default %q", mark)
	}
}
