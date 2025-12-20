package cidr

import (
	crand "crypto/rand"
	"math/rand/v2"
	"net"
	"slices"
	"testing"
)

func TestTrie(t *testing.T) {
	t.Run("InsertAndSearch", func(t *testing.T) {
		trie := NewTrie[string]()

		ip4 := func(s string) net.IP {
			return net.ParseIP(s).To4()
		}

		ip1 := ip4("8.8.8.8")
		ip2 := ip4("8.8.4.4")
		ip3 := ip4("1.2.3.4")

		trie.Insert(ip1, 32, "GroupA")
		got := trie.Search(ip1)
		if !slices.Contains(got, "GroupA") {
			t.Errorf("Expected GroupA, got %v", got)
		}

		trie.Insert(ip1, 32, "GroupB")
		got = trie.Search(ip1)
		if !slices.Contains(got, "GroupA") || !slices.Contains(got, "GroupB") || len(got) != 2 {
			t.Errorf("Expected GroupA and GroupB, got %v", got)
		}

		trie.Insert(ip2, 32, "GroupC")
		got = trie.Search(ip2)
		if !slices.Contains(got, "GroupC") || len(got) != 1 {
			t.Errorf("Expected GroupC, got %v", got)
		}

		got = trie.Search(ip3)
		if len(got) != 0 {
			t.Errorf("Expected no match for %v, got %v", ip3, got)
		}
	})

	t.Run("Remove", func(t *testing.T) {
		ip4 := func(s string) net.IP {
			return net.ParseIP(s).To4()
		}

		trie := NewTrie[string]()
		ip := ip4("8.8.8.8")

		trie.Insert(ip, 32, "GroupA")
		trie.Insert(ip, 32, "GroupB")

		trie.Remove(ip, 32, "GroupA")
		got := trie.Search(ip)
		if !slices.Contains(got, "GroupB") || len(got) != 1 {
			t.Errorf("Expected only GroupB, got %v", got)
		}

		trie.Remove(ip, 32, "GroupX")
		got = trie.Search(ip)
		if !slices.Contains(got, "GroupB") || len(got) != 1 {
			t.Errorf("Expected only GroupB after removing non-existing, got %v", got)
		}

		trie.Remove(ip, 32, "GroupB")
		got = trie.Search(ip)
		if len(got) != 0 {
			t.Errorf("Expected no match after removing all, got %v", got)
		}
	})

	t.Run("OverlappingPrefixes", func(t *testing.T) {
		ip4 := func(s string) net.IP {
			return net.ParseIP(s).To4()
		}

		trie := NewTrie[string]()

		trie.Insert(ip4("8.8.0.0"), 16, "GroupA")
		trie.Insert(ip4("8.8.8.0"), 24, "GroupB")
		trie.Insert(ip4("8.8.8.8"), 32, "GroupC")

		got := trie.Search(ip4("8.8.8.8"))
		expected := []string{"GroupA", "GroupB", "GroupC"}
		for _, e := range expected {
			if !slices.Contains(got, e) {
				t.Errorf("Expected %v, got %v", expected, got)
			}
		}

		got = trie.Search(ip4("8.8.8.100"))
		expected = []string{"GroupA", "GroupB"}
		for _, e := range expected {
			if !slices.Contains(got, e) {
				t.Errorf("Expected %v, got %v", expected, got)
			}
		}

		got = trie.Search(ip4("8.8.50.50"))
		expected = []string{"GroupA"}
		for _, e := range expected {
			if !slices.Contains(got, e) {
				t.Errorf("Expected %v, got %v", expected, got)
			}
		}

		got = trie.Search(ip4("1.2.3.4"))
		if len(got) != 0 {
			t.Errorf("Expected no match, got %v", got)
		}
	})
}

func BenchmarkTrie(b *testing.B) {
	b.Run("IPv4", func(b *testing.B) {
		ips := make([]net.IP, 1000)
		for i := range ips {
			ips[i] = net.IPv4(byte(rand.IntN(256)), byte(rand.IntN(256)), byte(rand.IntN(256)), byte(rand.IntN(256))).To4()
		}

		b.Run("Insert", func(b *testing.B) {
			trie := NewTrie[string]()
			b.ResetTimer()
			for i := 0; b.Loop(); i++ {
				trie.Insert(ips[i%len(ips)], 32, "benchmark")
			}
		})

		b.Run("Search", func(b *testing.B) {
			trie := NewTrie[string]()
			for _, ip := range ips {
				trie.Insert(ip, 32, "benchmark")
			}
			b.ResetTimer()
			for i := 0; b.Loop(); i++ {
				trie.Search(ips[i%len(ips)])
			}
		})
	})

	b.Run("IPv6", func(b *testing.B) {
		ips := make([]net.IP, 1000)
		for i := range ips {
			ip := make(net.IP, net.IPv6len)
			_, err := crand.Read(ip)
			if err != nil {
				b.Fatal(err)
			}
			ips[i] = ip
		}

		b.Run("Insert", func(b *testing.B) {
			trie := NewTrie[string]()
			b.ResetTimer()
			for i := 0; b.Loop(); i++ {
				trie.Insert(ips[i%len(ips)], 128, "benchmark")
			}
		})

		b.Run("Search", func(b *testing.B) {
			trie := NewTrie[string]()
			for _, ip := range ips {
				trie.Insert(ip, 128, "benchmark")
			}
			b.ResetTimer()
			for i := 0; b.Loop(); i++ {
				trie.Search(ips[i%len(ips)])
			}
		})
	})
}
