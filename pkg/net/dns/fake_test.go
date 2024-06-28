package dns

import (
	"fmt"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"go.etcd.io/bbolt"
)

func TestRetrieveIPFromPtr(t *testing.T) {
	t.Log(RetrieveIPFromPtr("f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.0.0.ip6.arpa."))
	t.Log(RetrieveIPFromPtr("1.2.0.10.in-addr.arpa."))
	t.Log(RetrieveIPFromPtr("4.9.0.0.a.1.8.6.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0.0.7.4.6.0.6.2.ip6.arpa."))
}

func TestNetip(t *testing.T) {
	t.Log(len("f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f"))
	addr, _ := netip.ParseAddr("2606:4700:20::681a:ffff")
	t.Log(addr.As16())

	z, err := netip.ParsePrefix("127.0.0.1/30")
	assert.NoError(t, err)

	nd, err := bbolt.Open("test.db", os.ModePerm, &bbolt.Options{})
	assert.NoError(t, err)
	defer nd.Close()

	ff := NewFakeIPPool(z, nd)
	defer ff.Flush()

	ch := make(chan struct {
		a  string
		ip netip.Addr
	}, 1000)

	go func() {
		for i := range ch {
			t.Log(i.a, i.ip)
		}
	}()

	getAndRev := func(a string) {
		ip := ff.GetFakeIPForDomain(a)
		ch <- struct {
			a  string
			ip netip.Addr
		}{
			a, ip,
		}
	}

	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()
		getAndRev(fmt.Sprint(1))
	}()

	now := time.Now()
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			getAndRev(fmt.Sprint(i))
		}()
	}

	wg.Wait()
	t.Log(time.Since(now))

	// bbolt 630ms 673ms 624ms
	// badger 130ms 112ms 103ms
}
