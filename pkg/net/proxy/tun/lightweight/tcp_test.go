package lightweight

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"
)

func TestTCPBidirectionalHalfClose(t *testing.T) {
	for _, dst := range []string{"192.0.2.2:8080", "[2001:db8::2]:8080"} {
		t.Run(dst, func(t *testing.T) {
			a, b := stackPair(t)
			l, err := b.ListenTCP(netip.MustParseAddrPort(dst))
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			client, err := a.DialContextTCP(ctx, netip.MustParseAddrPort(dst))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			server, err := l.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))
			_ = server.SetDeadline(time.Now().Add(5 * time.Second))
			payload := bytes.Repeat([]byte("ordered transport!"), 12000)
			write := make(chan error, 1)
			go func() {
				_, e := client.Write(payload)
				if e == nil {
					e = client.(interface{ CloseWrite() error }).CloseWrite()
				}
				write <- e
			}()
			got, err := io.ReadAll(server)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("data: %d/%d, %v", len(got), len(payload), err)
			}
			if err := <-write; err != nil {
				t.Fatal(err)
			}
			if _, err := server.Write([]byte("after peer FIN")); err != nil {
				t.Fatal(err)
			}
			if err := server.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			reply, err := io.ReadAll(client)
			if err != nil || string(reply) != "after peer FIN" {
				t.Fatalf("half close: %q %v", reply, err)
			}
		})
	}
}

func TestTCPDialCancelAndDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m, _ := memoryPair()
		s, err := New(Config{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}, m)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		_, err = s.DialContextTCP(ctx, netip.MustParseAddrPort("192.0.2.2:80"))
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("cancel: %v", err)
		}
		if s.Stats().Connections != 0 {
			t.Fatal("canceled dial retained flow")
		}
	})
}

func TestTCPListenerClose(t *testing.T) {
	a, b := stackPair(t)
	l, err := b.ListenTCP(netip.MustParseAddrPort("192.0.2.2:80"))
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	if _, err = l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed accept: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err = a.DialContextTCP(ctx, netip.MustParseAddrPort("192.0.2.2:80")); err == nil {
		t.Fatal("connected to closed listener")
	}
}
