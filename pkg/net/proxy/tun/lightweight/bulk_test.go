package lightweight

import (
	"bytes"
	"io"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"
)

func TestUnimpairedMTUBulkDoesNotRetransmit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for _, mtu := range []int{1280, 1500, 9000} {
			x, y := memoryPair()
			a, err := New(Config{MTU: mtu, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}, x)
			if err != nil {
				t.Fatal(err)
			}
			z, err := New(Config{MTU: mtu, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.2")}}, y)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = a.Close(); _ = z.Close() })
			l, err := z.ListenTCP(netip.MustParseAddrPort("192.0.2.2:8080"))
			if err != nil {
				t.Fatal(err)
			}
			client, err := a.DialContextTCP(t.Context(), netip.MustParseAddrPort("192.0.2.2:8080"))
			if err != nil {
				t.Fatal(err)
			}
			server, err := l.Accept()
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				marker := make([]byte, 1)
				_, err := io.ReadFull(server, marker)
				if err == nil {
					_, err = server.Write(bytes.Repeat([]byte{0xa5}, 65536))
				}
				done <- err
			}()
			started := time.Now()
			if _, err = client.Write([]byte{1}); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 65536)
			_, err = io.ReadFull(client, buf)
			if err != nil {
				t.Fatal(err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
			if a.Stats().Retransmissions+z.Stats().Retransmissions > 0 {
				t.Fatalf("MTU %d no-loss bulk needed retransmission after %v: %+v %+v", mtu, time.Since(started), a.Stats(), z.Stats())
			}
			_ = client.Close()
			_ = server.Close()
			_ = l.Close()
			_ = a.Close()
			_ = z.Close()
		}
	})
}
