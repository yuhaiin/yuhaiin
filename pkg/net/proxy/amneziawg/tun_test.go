package amneziawg

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
)

func TestLightweightTunAdapterDatagrams(t *testing.T) {
	create := func(ipv4, ipv6 string) *tunAdapter {
		t.Helper()
		n, err := wireguard.CreateLightweightNetTUN([]netip.Prefix{netip.MustParsePrefix(ipv4), netip.MustParsePrefix(ipv6)}, 1400)
		if err != nil {
			t.Fatal(err)
		}
		return newTunAdapter(n)
	}
	a, b := create("192.0.2.1/32", "2001:db8::1/128"), create("192.0.2.2/32", "2001:db8::2/128")
	var pumps sync.WaitGroup
	pump := func(src, dst *tunAdapter) {
		bufs := [][]byte{make([]byte, 1532)}
		sizes := make([]int, 1)
		for {
			count, err := src.Read(bufs, sizes, 32)
			if err != nil {
				return
			}
			if count != 1 {
				t.Error("adapter read returned incorrect packet count")
				return
			}
			if n, err := dst.Write([][]byte{bufs[0][:32+sizes[0]]}, 32); err != nil || n != 1 {
				return
			}
		}
	}
	pumps.Go(func() { pump(a, b) })
	pumps.Go(func() { pump(b, a) })
	t.Cleanup(func() { _ = a.Close(); _ = b.Close(); pumps.Wait() })
	client, err := a.net.DialUDP(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	for _, dst := range []string{"192.0.2.2:9000", "[2001:db8::2]:9000"} {
		addr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort(dst))
		server, err := b.net.DialUDP(addr, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		_ = server.SetDeadline(time.Now().Add(5 * time.Second))
		payload := bytes.Repeat([]byte("adapter offset data"), 50)
		if _, err := client.WriteTo(payload, addr); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1400)
		n, from, err := server.ReadFrom(buf)
		if err != nil || !bytes.Equal(buf[:n], payload) {
			t.Fatalf("adapter request: %d, %v", n, err)
		}
		if _, err := server.WriteTo(buf[:n], from); err != nil {
			t.Fatal(err)
		}
		n, from, err = client.ReadFrom(buf)
		if err != nil || !bytes.Equal(buf[:n], payload) || from.String() != dst {
			t.Fatalf("adapter reply: %d from %v, %v", n, from, err)
		}
	}
	for _, offset := range []int{-1, 100} {
		if _, err := a.Read([][]byte{make([]byte, 10)}, make([]int, 1), offset); !errors.Is(err, io.ErrShortBuffer) {
			t.Fatalf("invalid read offset: %v", err)
		}
		if _, err := a.Write([][]byte{make([]byte, 10)}, offset); err == nil {
			t.Fatal("invalid write offset accepted")
		}
	}
}
