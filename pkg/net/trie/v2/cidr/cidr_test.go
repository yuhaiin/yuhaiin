package cidr

import (
	crand "crypto/rand"
	"math/rand/v2"
	"net/netip"
	"testing"
)

func TestCidr(t *testing.T) {
	t.Run("InsertAndSearch", func(t *testing.T) {
		c := NewCidr[string]()
		err := c.Insert("192.168.1.0/24", "lan")
		if err != nil {
			t.Fatalf("insert failed: %v", err)
		}
		res := c.Search("192.168.1.100")
		if !res.Has("lan") {
			t.Error("expected to find lan")
		}
	})

	t.Run("Remove", func(t *testing.T) {
		c := NewCidr[string]()
		c.Insert("192.168.1.0/24", "lan")
		c.Insert("192.168.1.0/24", "private")
		c.Insert("192.168.1.1/32", "host")

		// Before removal
		res := c.Search("192.168.1.1")
		if !res.ContainsAll("lan", "private", "host") {
			t.Errorf("expected lan, private, host, got %v", res)
		}

		// Remove the /24 prefix marks
		prefix, _ := netip.ParsePrefix("192.168.1.0/24")
		c.RemoveCIDR(prefix)

		// After removal
		res = c.Search("192.168.1.2")
		if res.Len() != 0 {
			t.Errorf("expected no marks for /24, got %v", res)
		}

		res = c.Search("192.168.1.1")
		if !res.Has("host") || res.Len() != 1 {
			t.Errorf("expected only host mark, got %v", res)
		}
	})
}

func BenchmarkCidr(b *testing.B) {
	b.Run("IPv4", func(b *testing.B) {
		cidrs := make([]string, 1000)
		ips := make([]string, 1000)
		for i := range cidrs {
			addr := netip.AddrFrom4([4]byte{byte(rand.IntN(256)), byte(rand.IntN(256)), byte(rand.IntN(256)), byte(rand.IntN(256))})
			cidrs[i] = netip.PrefixFrom(addr, 32).String()
			ips[i] = addr.String()
		}

		b.Run("Insert", func(b *testing.B) {
			c := NewCidr[string]()
			b.ResetTimer()
			for i := 0; b.Loop(); i++ {
				c.Insert(cidrs[i%len(cidrs)], "benchmark")
			}
		})

		b.Run("Search", func(b *testing.B) {
			c := NewCidr[string]()
			for _, cidr := range cidrs {
				c.Insert(cidr, "benchmark")
			}
			b.ResetTimer()
			for i := 0; b.Loop(); i++ {
				c.Search(ips[i%len(ips)])
			}
		})
	})

	b.Run("IPv6", func(b *testing.B) {
		cidrs := make([]string, 1000)
		ips := make([]string, 1000)
		for i := range cidrs {
			var addrBytes [16]byte
			_, err := crand.Read(addrBytes[:])
			if err != nil {
				b.Fatal(err)
			}
			addr := netip.AddrFrom16(addrBytes)
			cidrs[i] = netip.PrefixFrom(addr, 128).String()
			ips[i] = addr.String()
		}

		b.Run("Insert", func(b *testing.B) {
			c := NewCidr[string]()
			b.ResetTimer()
			for i := 0; b.Loop(); i++ {
				c.Insert(cidrs[i%len(cidrs)], "benchmark")
			}
		})

		b.Run("Search", func(b *testing.B) {
			c := NewCidr[string]()
			for _, cidr := range cidrs {
				c.Insert(cidr, "benchmark")
			}
			b.ResetTimer()
			for i := 0; b.Loop(); i++ {
				c.Search(ips[i%len(ips)])
			}
		})
	})

	b.Run("Mixed", func(b *testing.B) {
		cidrs4 := make([]string, 1000)
		ips4 := make([]string, 1000)
		for i := range cidrs4 {
			addr := netip.AddrFrom4([4]byte{byte(rand.IntN(256)), byte(rand.IntN(256)), byte(rand.IntN(256)), byte(rand.IntN(256))})
			cidrs4[i] = netip.PrefixFrom(addr, 32).String()
			ips4[i] = addr.String()
		}

		cidrs6 := make([]string, 1000)
		ips6 := make([]string, 1000)
		for i := range cidrs6 {
			var addrBytes [16]byte
			_, err := crand.Read(addrBytes[:])
			if err != nil {
				b.Fatal(err)
			}
			addr := netip.AddrFrom16(addrBytes)
			cidrs6[i] = netip.PrefixFrom(addr, 128).String()
			ips6[i] = addr.String()
		}
		
		allIps := append(ips4, ips6...)

		b.Run("Search", func(b *testing.B) {
			c := NewCidr[string]()
			for _, cidr := range cidrs4 {
				c.Insert(cidr, "benchmark")
			}
			for _, cidr := range cidrs6 {
				c.Insert(cidr, "benchmark")
			}
			b.ResetTimer()
			for i := 0; b.Loop(); i++ {
				c.Search(allIps[i%len(allIps)])
			}
		})
	})
}