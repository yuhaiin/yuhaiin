package resolver

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	ybbolt "github.com/Asutorufa/yuhaiin/pkg/utils/cache/bbolt"
	"go.etcd.io/bbolt"
)

func TestRetrieveIPFromPtr(t *testing.T) {
	for _, v := range []struct {
		ptr    string
		error  bool
		expect net.IP
	}{
		{
			"f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.0.0.ip6.arpa.",
			false,
			net.ParseIP("ff::ff"),
		},
		{
			"1.2.0.10.in-addr.arpa.",
			false,
			net.ParseIP("10.0.2.1").To4(),
		},
		{
			"2.1.2.0.10.in-addr.arpa.",
			true,
			nil,
		},
		{
			"1.256.0.10.in-addr.arpa.",
			true,
			nil,
		},
		{
			"255.255.255.255.in-addr.arpa.",
			false,
			net.IPv4(255, 255, 255, 255).To4(),
		},
		{
			"4.9.0.0.a.1.8.6.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0.0.7.4.6.0.6.2.ip6.arpa.",
			false,
			net.ParseIP("2606:4700:20::681a:94"),
		},
		{
			"b._dns-sd._udp.0.1.17.172.in-addr.arpa.",
			true,
			nil,
		},
		{
			"b._dns-sd._udp.4.9.0.0.a.1.8.6.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0.0.7.4.6.0.6.2.ip6.arpa.",
			true,
			nil,
		},
	} {
		ip, err := RetrieveIPFromPtr(v.ptr)
		if v.error {
			assert.Error(t, err)
			t.Log(err)
		} else {
			assert.EqualAny(t, ip, v.expect, slices.Equal)
		}
	}
}

func TestNetip(t *testing.T) {
	slog.SetLogLoggerLevel(slog.LevelDebug)

	t.Log(len("f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f"))
	addr, _ := netip.ParseAddr("2606:4700:20::681a:ffff")
	t.Log(addr.As16())

	z, err := netip.ParsePrefix("127.0.0.1/30")
	assert.NoError(t, err)

	nd, err := bbolt.Open("test.db", os.ModePerm, &bbolt.Options{})
	assert.NoError(t, err)
	defer nd.Close()

	ff := NewFakeIPPool(z, ybbolt.NewCache(nd))
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

func BenchmarkParsePtr(b *testing.B) {
	old := func(name string) (net.IP, error) {
		if strings.HasSuffix(name, arpaV6Suffix) && len(name)-arpaV6SuffixLen == arpaV6MaxIPLen {
			var ip [16]byte
			for i := range ip {
				ip[i] = fromHexByte(name[62-i*4])*16 + fromHexByte(name[62-i*4-2])
			}
			return ip[:], nil
		}

		if !strings.HasSuffix(name, arpaV4Suffix) {
			return nil, fmt.Errorf("retrieve ip from ptr failed: %s", name)
		}

		reverseIPv4, err := netip.ParseAddr(name[:len(name)-arpaV4SuffixLen])
		if err != nil || !reverseIPv4.Is4() {
			return nil, fmt.Errorf("retrieve ip from ptr failed: %s, %w", name, err)
		}

		ipv4 := reverseIPv4.As4()
		slices.Reverse(ipv4[:])
		return ipv4[:], nil
	}

	b.Run("old", func(b *testing.B) {
		for b.Loop() {
			_, _ = old("2.1.2.0.10.in-addr.arpa.")
		}
	})

	b.Run("new", func(b *testing.B) {
		for b.Loop() {
			_, _ = RetrieveIPFromPtr("2.1.2.0.10.in-addr.arpa.")
		}
	})
}
