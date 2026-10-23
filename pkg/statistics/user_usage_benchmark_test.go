package statistics

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
)

// Reuse precisely the existing payload counters with/without the observer.
// The enabled variant includes the running sampler and SQLite batch writer.
func BenchmarkUserUsageCounter(b *testing.B) {
	for _, enabled := range []bool{false, true} {
		b.Run(fmt.Sprint(enabled), func(b *testing.B) {
			quietRelayBenchmarkLogs(b)
			c := NewSQLiteConnStore(filepath.Join(b.TempDir(), "state.db"), nil)
			defer c.Close()
			counter := newCounter(c.Cache, nil)
			if enabled {
				r, err := c.EnableUserUsage(DefaultUsageOptions())
				if err != nil {
					b.Fatal(err)
				}
				s := r.register(usageInfo("alice", "phone", "node"), counter, nil)
				defer s.end()
			}
			b.ReportAllocs()
			for b.Loop() {
				counter.AddUpload(16384)
				counter.AddDownload(16384)
			}
		})
	}
}

func BenchmarkUserUsageSample(b *testing.B) {
	for _, count := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			r := usageTestRecorder(b)
			counters := make([]*usageTestCounter, count)
			for i := range count {
				counters[i] = new(usageTestCounter)
				r.register(usageInfo(fmt.Sprint(i%100), fmt.Sprint(i%64), fmt.Sprint(i%4)), counters[i], nil)
			}
			b.ReportAllocs()
			for b.Loop() {
				for _, c := range counters {
					c.upload.Add(16384)
					c.download.Add(16384)
				}
				r.sample(time.Now())
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count), "ns/session")
		})
	}
}

func BenchmarkUserUsageFlush(b *testing.B) {
	for _, count := range []int{100, 1000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			r := usageTestRecorder(b)
			counters := make([]*usageTestCounter, count)
			for i := range count {
				counters[i] = new(usageTestCounter)
				r.register(usageInfo(fmt.Sprint(i%100), fmt.Sprint(i%64), fmt.Sprint(i%4)), counters[i], nil)
			}
			r.sample(time.Now())
			if err := r.Flush(b.Context()); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				for _, c := range counters {
					c.upload.Add(16384)
					c.download.Add(16384)
				}
				r.sample(time.Now())
				if err := r.Flush(b.Context()); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*count), "ns/session")
		})
	}
}

type usageBenchmarkConn struct{}

func (usageBenchmarkConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (usageBenchmarkConn) Write(p []byte) (int, error) { return len(p), nil }
func (usageBenchmarkConn) Close() error                { return nil }
func (usageBenchmarkConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}
func (usageBenchmarkConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
}
func (usageBenchmarkConn) SetDeadline(time.Time) error      { return nil }
func (usageBenchmarkConn) SetReadDeadline(time.Time) error  { return nil }
func (usageBenchmarkConn) SetWriteDeadline(time.Time) error { return nil }

func usageBenchmarkContext(b *testing.B) *netapi.Context {
	ctx := netapi.WithContext(netapi.WithTrafficIdentity(b.Context(), &proxyauth.Identity{UserID: "alice", CredentialID: "phone", Context: b.Context()}))
	ctx.SetInboundID("entry")
	ctx.Hash, ctx.NodeName = "node", "Node"
	return ctx
}

// Commit both the existing connection history and new usage/audit batches
// inside the timed loop; shutdown must not hide the cost of persistence.
func BenchmarkUserUsageLifecycle(b *testing.B) {
	for _, enabled := range []bool{false, true} {
		for _, burst := range []int{1, 32} {
			b.Run(fmt.Sprintf("%t/%d", enabled, burst), func(b *testing.B) {
				quietRelayBenchmarkLogs(b)
				c := NewSQLiteConnStore(filepath.Join(b.TempDir(), "state.db"), relayConnProxy{conn: usageBenchmarkConn{}})
				defer c.Close()
				var recorder *UserUsage
				if enabled {
					var err error
					recorder, err = c.EnableUserUsage(DefaultUsageOptions())
					if err != nil {
						b.Fatal(err)
					}
				}
				ctx := usageBenchmarkContext(b)
				b.ReportAllocs()
				for b.Loop() {
					for range burst {
						conn, err := c.Conn(ctx, netapi.EmptyAddr)
						if err != nil {
							b.Fatal(err)
						}
						if _, err := conn.Write([]byte("payload")); err != nil {
							b.Fatal(err)
						}
						_ = conn.Close()
					}
					if _, err := c.AllHistory(b.Context()); err != nil {
						b.Fatal(err)
					}
					if recorder != nil {
						recorder.sample(time.Now())
						if err := recorder.Flush(b.Context()); err != nil {
							b.Fatal(err)
						}
					}
				}
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*burst), "ns/flow")
			})
		}
	}
}

// Real loopback TCP echo, using production Connections.Conn and its normal
// upload/download counters. Run each enabled/disabled case in an independent
// process for CPU time and max-RSS measurements (see docs/user-usage.md).
func BenchmarkUserUsageTCPRelay(b *testing.B) {
	for _, enabled := range []bool{false, true} {
		b.Run(fmt.Sprint(enabled), func(b *testing.B) {
			quietRelayBenchmarkLogs(b)
			target, finish := usageTCPBenchmarkPeer(b)
			c := NewSQLiteConnStore(filepath.Join(b.TempDir(), "state.db"), nil)
			defer c.Close()
			if enabled {
				if _, err := c.EnableUserUsage(DefaultUsageOptions()); err != nil {
					b.Fatal(err)
				}
			}
			address, err := netapi.ParseAddress("tcp", target)
			if err != nil {
				b.Fatal(err)
			}
			stream, err := c.Conn(usageBenchmarkContext(b), address)
			if err != nil {
				b.Fatal(err)
			}
			defer stream.Close()
			readDone := make(chan error, 1)
			go func() { _, err := io.Copy(io.Discard, stream); readDone <- err }()
			payload := make([]byte, 16384)
			b.ReportAllocs()
			b.SetBytes(int64(2 * len(payload)))
			for b.Loop() {
				if _, err := stream.Write(payload); err != nil {
					b.Fatal(err)
				}
			}
			// Include draining outstanding echo traffic in the measured duration.
			b.StartTimer()
			if err := stream.(*conn).Conn.(*net.TCPConn).CloseWrite(); err != nil {
				b.Fatal(err)
			}
			if err := <-readDone; err != nil {
				b.Fatal(err)
			}
			finish()
			b.StopTimer()
			want := uint64(b.N * len(payload))
			if c.Cache.LoadUpload() != want || c.Cache.LoadDownload() != want {
				b.Fatalf("traffic=%d/%d want %d", c.Cache.LoadUpload(), c.Cache.LoadDownload(), want)
			}
		})
	}
}

func BenchmarkUserUsageIdleMemory(b *testing.B) {
	for _, enabled := range []bool{false, true} {
		b.Run(fmt.Sprint(enabled), func(b *testing.B) {
			quietRelayBenchmarkLogs(b)
			c := NewSQLiteConnStore(filepath.Join(b.TempDir(), "state.db"), relayConnProxy{conn: usageBenchmarkConn{}})
			defer c.Close()
			if enabled {
				if _, err := c.EnableUserUsage(DefaultUsageOptions()); err != nil {
					b.Fatal(err)
				}
			}
			ctx := usageBenchmarkContext(b)
			const count = 1000
			var retained uint64
			for b.Loop() {
				b.StopTimer()
				runtime.GC()
				var before runtime.MemStats
				runtime.ReadMemStats(&before)
				b.StartTimer()
				conns := make([]net.Conn, 0, count)
				for range count {
					conn, err := c.Conn(ctx, netapi.EmptyAddr)
					if err != nil {
						b.Fatal(err)
					}
					conns = append(conns, conn)
				}
				b.StopTimer()
				if err := c.persistence.flush(); err != nil {
					b.Fatal(err)
				}
				runtime.GC()
				var after runtime.MemStats
				runtime.ReadMemStats(&after)
				if after.HeapAlloc > before.HeapAlloc {
					retained += after.HeapAlloc - before.HeapAlloc
				}
				for _, conn := range conns {
					_ = conn.Close()
				}
				if c.userUsage != nil {
					c.userUsage.sample(time.Now())
					if err := c.userUsage.Flush(context.Background()); err != nil {
						b.Fatal(err)
					}
				}
				b.StartTimer()
			}
			b.ReportMetric(float64(retained)/float64(b.N*count), "heap-B/session")
		})
	}
}

// One request/reply per iteration, with real UDP sockets and no pipelining.
// This measures datagram latency/counter overhead rather than WAN capacity.
func BenchmarkUserUsageUDPRoundTrip(b *testing.B) {
	for _, enabled := range []bool{false, true} {
		b.Run(fmt.Sprint(enabled), func(b *testing.B) {
			quietRelayBenchmarkLogs(b)
			target, finish := usageUDPBenchmarkPeer(b)
			defer finish()
			c := NewSQLiteConnStore(filepath.Join(b.TempDir(), "state.db"), nil)
			defer c.Close()
			if enabled {
				if _, err := c.EnableUserUsage(DefaultUsageOptions()); err != nil {
					b.Fatal(err)
				}
			}
			address, err := netapi.ParseAddress("udp", target.String())
			if err != nil {
				b.Fatal(err)
			}
			stream, err := c.PacketConn(usageBenchmarkContext(b), address)
			if err != nil {
				b.Fatal(err)
			}
			defer stream.Close()
			if err := stream.SetDeadline(time.Now().Add(2 * time.Minute)); err != nil {
				b.Fatal(err)
			}
			payload, reply := make([]byte, 1350), make([]byte, 2048)
			b.ReportAllocs()
			b.SetBytes(2700)
			for b.Loop() {
				if _, err := stream.WriteTo(payload, target); err != nil {
					b.Fatal(err)
				}
				if n, _, err := stream.ReadFrom(reply); err != nil || n != len(payload) {
					b.Fatalf("reply=%d %v", n, err)
				}
			}
			want := uint64(b.N * len(payload))
			if c.Cache.LoadUpload() != want || c.Cache.LoadDownload() != want {
				b.Fatalf("traffic=%d/%d want %d", c.Cache.LoadUpload(), c.Cache.LoadDownload(), want)
			}
		})
	}
}

func usageTCPBenchmarkPeer(b *testing.B) (string, func()) {
	b.Helper()
	if target := os.Getenv("YUHAIIN_USAGE_BENCH_TCP_TARGET"); target != "" {
		return target, func() {}
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = listener.Close() })
	done := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer raw.Close()
		_, err = io.Copy(raw, raw)
		done <- err
	}()
	return listener.Addr().String(), func() {
		if err := <-done; err != nil {
			b.Fatal(err)
		}
	}
}

func usageUDPBenchmarkPeer(b *testing.B) (net.Addr, func()) {
	b.Helper()
	if target := os.Getenv("YUHAIIN_USAGE_BENCH_UDP_TARGET"); target != "" {
		address, err := net.ResolveUDPAddr("udp4", target)
		if err != nil {
			b.Fatal(err)
		}
		return address, func() {}
	}
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, peer, err := server.ReadFrom(buffer)
			if err != nil {
				done <- err
				return
			}
			if _, err := server.WriteTo(buffer[:n], peer); err != nil {
				done <- err
				return
			}
		}
	}()
	return server.LocalAddr(), func() {
		_ = server.Close()
		if err := <-done; !errors.Is(err, net.ErrClosed) {
			b.Fatal(err)
		}
	}
}
