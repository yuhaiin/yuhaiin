package resolver

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"

	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestFakednsDefaultPools(t *testing.T) {
	f, err := NewFakeDNS(
		netapi.NewErrProxy(errors.New("test dialer")),
		netapi.ErrorResolver(func(string) error { return nil }),
		t.TempDir()+"/state.db",
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	ipv4 := netip.MustParsePrefix("198.18.0.0/16")
	ipv6 := netip.MustParsePrefix("2001:2::/64")
	if !f.fake.Equal(ipv4, ipv6) {
		t.Fatal("constructor did not use the default benchmarking pools")
	}
	initial := f.fake
	f.Apply(contractresolver.FakeDNS{})
	if f.fake != initial {
		t.Fatal("applying empty settings replaced the default pools")
	}
}

func TestFakednsDispatchAddrConcurrentClose(t *testing.T) {
	f, err := NewFakeDNS(
		netapi.NewErrProxy(errors.New("test dialer")),
		netapi.ErrorResolver(func(string) error { return nil }),
		t.TempDir()+"/state.db",
	)
	if err != nil {
		t.Fatal(err)
	}

	addr, err := netapi.ParseAddress("tcp", "198.18.0.1:443")
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			<-start
			for range 1000 {
				_ = f.dispatchAddr(context.Background(), addr)
			}
		})
	}
	closed := make(chan struct{})
	go func() {
		<-start
		_ = f.Close()
		close(closed)
	}()

	close(start)
	wg.Wait()
	<-closed

	if got := f.dispatchAddr(context.Background(), addr); got != addr {
		t.Fatalf("dispatch after close returned %v, want original address %v", got, addr)
	}
}
