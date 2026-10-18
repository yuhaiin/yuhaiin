package cert

import (
	"bytes"
	"crypto/x509"
	"net"
	"sync"
	"testing"
	"time"
)

func TestCertificateCacheConcurrencyExpiryAndSANs(t *testing.T) {
	ca, err := GenerateCa()
	if err != nil {
		t.Fatal(err)
	}
	root, err := ca.CertBytes()
	if err != nil {
		t.Fatal(err)
	}
	again, _ := ca.CertBytes()
	if !bytes.Equal(root, again) {
		t.Fatal("root export changed fingerprint")
	}
	cache := NewCache(ca, 2)
	var certificates sync.Map
	var workers sync.WaitGroup
	for range 32 {
		workers.Go(func() {
			leaf, err := cache.Get(x509.ECDSA, "example.com", "127.0.0.1")
			if err != nil {
				t.Error(err)
				return
			}
			certificates.Store(leaf, struct{}{})
		})
	}
	workers.Wait()
	count := 0
	certificates.Range(func(_, _ any) bool { count++; return true })
	if count != 1 {
		t.Fatalf("generated %d leaf certificates for one concurrent miss", count)
	}
	leaf, err := cache.Get(x509.ECDSA, "example.com", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(root)
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "example.com"}); err != nil {
		t.Fatal(err)
	}
	if !leaf.Leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatal("missing IP SAN")
	}
	if time.Until(leaf.Leaf.NotAfter) > 31*24*time.Hour {
		t.Fatal("leaf lifetime exceeds 30 days")
	}
	leaf.Leaf.NotAfter = time.Now().Add(time.Minute)
	renewed, err := cache.Get(x509.ECDSA, "example.com", "127.0.0.1")
	if err != nil || renewed == leaf {
		t.Fatal("expiring leaf not renewed")
	}
	for _, host := range []string{"a.example", "b.example", "c.example"} {
		if _, err := cache.Get(x509.ECDSA, host); err != nil {
			t.Fatal(err)
		}
	}
	if cache.Len() != 2 {
		t.Fatalf("cache exceeded capacity: %d", cache.Len())
	}
}

func TestImportedCARequiresMatchingKey(t *testing.T) {
	first, err := GenerateCa()
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateCa()
	if err != nil {
		t.Fatal(err)
	}
	root, _ := first.CertBytes()
	wrongKey, _ := second.PrivateKeyBytes()
	if _, err := ParseCa(root, wrongKey); err == nil {
		t.Fatal("accepted mismatched CA key")
	}
}
