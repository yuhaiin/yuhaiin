package resolver

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestFakednsDispatchAddrConcurrentClose(t *testing.T) {
	f, err := NewFakeDNS(
		netapi.NewErrProxy(errors.New("test dialer")),
		netapi.ErrorResolver(func(string) error { return nil }),
		t.TempDir()+"/state.db",
	)
	if err != nil {
		t.Fatal(err)
	}

	addr, err := netapi.ParseAddress("tcp", "10.2.0.1:443")
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
