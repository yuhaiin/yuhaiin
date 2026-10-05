package http2

import (
	"bytes"
	"context"
	"fmt"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	"io"
	"net"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// Exercise the real HTTP/2 client and server through a local TCP socket.
func BenchmarkTunnelRoundTrip(b *testing.B) {
	for _, size := range []int{64, 16384, 65536} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			lis, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			srv := newServer(lis)
			defer srv.Close()
			host, portText, _ := net.SplitHostPort(srv.Addr().String())
			port, _ := strconv.Atoi(portText)
			base, err := fixed.NewClient(fixed.Config{Host: host, Port: int32(port)}, nil)
			if err != nil {
				b.Fatal(err)
			}
			client, err := NewClient(Config{Concurrency: 10}, base)
			if err != nil {
				b.Fatal(err)
			}
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := client.Conn(ctx, netapi.EmptyAddr)
			if err != nil {
				b.Fatal(err)
			}
			defer conn.Close()
			peer, err := acceptWithContext(ctx, srv)
			if err != nil {
				b.Fatal(err)
			}
			defer peer.Close()
			_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
			_ = peer.SetDeadline(time.Now().Add(30 * time.Second))
			done := make(chan struct{})
			go func() {
				defer close(done)
				buf := make([]byte, 16384)
				for {
					n, err := peer.Read(buf)
					if n > 0 {
						if _, err := peer.Write(buf[:n]); err != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
			payload, reply := make([]byte, size), make([]byte, size)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				if _, err := conn.Write(payload); err != nil {
					b.Fatal(err)
				}
				if _, err := io.ReadFull(conn, reply); err != nil {
					b.Fatal(err)
				}
			}
			_ = conn.Close()
			_ = peer.Close()
			<-done
		})
	}
}

func TestTunnelLargePayloadIntegrity(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer(lis)
	defer srv.Close()
	host, portText, _ := net.SplitHostPort(srv.Addr().String())
	port, _ := strconv.Atoi(portText)
	base, err := fixed.NewClient(fixed.Config{Host: host, Port: int32(port)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(Config{Concurrency: 10}, base)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := range 4 {
		conn, err := client.Conn(ctx, netapi.EmptyAddr)
		if err != nil {
			t.Fatal(err)
		}
		peer, err := acceptWithContext(ctx, srv)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
		done := make(chan struct{})
		go func() { defer close(done); _, _ = io.Copy(peer, peer) }()
		payload := make([]byte, 256*1024)
		for j := range payload {
			payload[j] = byte(j*17 + i)
		}
		writeDone := make(chan error, 1)
		go func() { _, err := conn.Write(payload); writeDone <- err }()
		reply := make([]byte, len(payload))
		_, readErr := io.ReadFull(conn, reply)
		_ = conn.Close()
		_ = peer.Close()
		<-done
		writeErr := <-writeDone
		if readErr != nil || writeErr != nil {
			t.Fatalf("transfer error: %v/%v", readErr, writeErr)
		}
		if !bytes.Equal(reply, payload) {
			t.Fatal("corrupted data across HTTP/2 frame boundaries")
		}
	}
}

// Measure the live heap of an idle batch separately from request throughput.
// Every sample keeps both endpoints open across two GCs, including the real
// HTTP/2 transport's request-body buffers and relay goroutines.
func BenchmarkIdleTunnels(b *testing.B) {
	const count = 128
	var retained uint64
	for b.Loop() {
		b.StopTimer()
		runtime.GC()
		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)
		b.StartTimer()
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatal(err)
		}
		srv := newServer(lis)
		client, err := NewClient(Config{}, &addressDialer{addr: lis.Addr().String()})
		if err != nil {
			b.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(b.Context(), 10*time.Second)
		conns := make([]net.Conn, 0, count*2)
		for range count {
			conn, err := client.Conn(ctx, netapi.EmptyAddr)
			if err != nil {
				b.Fatal(err)
			}
			peer, err := acceptWithContext(ctx, srv)
			if err != nil {
				b.Fatal(err)
			}
			conns = append(conns, conn, peer)
		}
		b.StopTimer()
		time.Sleep(10 * time.Millisecond)
		runtime.GC()
		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		if after.HeapAlloc > before.HeapAlloc {
			retained += after.HeapAlloc - before.HeapAlloc
		}
		for _, conn := range conns {
			_ = conn.Close()
		}
		cancel()
		_ = client.Close()
		_ = srv.Close()
		runtime.KeepAlive(conns)
		b.StartTimer()
	}
	b.ReportMetric(float64(retained)/float64(b.N*count), "retained-B/tunnel")
}
