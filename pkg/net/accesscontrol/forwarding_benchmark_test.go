package accesscontrol

import (
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// Loopback plaintext echo measures the established stream wrapper. It excludes
// handshake throughput, encryption, remote RTT, DNS, and physical link shaping.
func BenchmarkAccessTCPForwarding(b *testing.B) {
	for _, mode := range []string{"Absent", "Disabled", "Protected"} {
		b.Run(mode, func(b *testing.B) {
			var capability netapi.TrafficAccess
			if mode != "Absent" {
				c := New()
				defer c.Close()
				capability = c
				if mode == "Protected" {
					install(b, c, config(groupRule("finance", "allow", "finance")))
				}
			}
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			defer listener.Close()
			peerDone := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					peerDone <- err
					return
				}
				defer conn.Close()
				_, err = io.Copy(conn, conn)
				peerDone <- err
			}()
			owner := subject(b.Context(), "alice", "finance")
			ctx := netapi.WithContext(netapi.WithTrafficIdentity(b.Context(), owner.Identity))
			ctx.SetInboundID("entry")
			dst := address(b, "tcp", listener.Addr().String())
			conn, err := netapi.DialTraffic(ctx, capability, dst, dst, func(ctx context.Context, dst netapi.Address) (net.Conn, error) {
				return new(net.Dialer).DialContext(ctx, "tcp", dst.String())
			})
			if err != nil {
				b.Fatal(err)
			}
			defer conn.Close()
			readDone := make(chan error, 1)
			go func() { _, err := io.Copy(io.Discard, conn); readDone <- err }()
			payload := make([]byte, 16384)
			b.SetBytes(int64(2 * len(payload)))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := conn.Write(payload); err != nil {
					b.Fatal(err)
				}
			}
			b.StartTimer()
			if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				b.Fatal(err)
			}
			if err := <-readDone; err != nil {
				b.Fatal(err)
			}
			if err := <-peerDone; err != nil {
				b.Fatal(err)
			}
			b.StopTimer()
		})
	}
}

func BenchmarkAccessAdmission(b *testing.B) {
	c := New()
	defer c.Close()
	install(b, c, config(groupRule("finance", "allow", "finance")))
	owner := subject(b.Context(), "alice", "finance")
	dst := address(b, "tcp", "203.0.113.2:443")
	b.ReportAllocs()
	for b.Loop() {
		s, err := c.NewSession(owner, func(error) {})
		if err != nil {
			b.Fatal(err)
		}
		if err := s.Authorize(dst, dst); err != nil {
			b.Fatal(err)
		}
		s.Close()
	}
}

func BenchmarkAccessIdleMemory1024(b *testing.B) {
	c := New()
	defer c.Close()
	install(b, c, config(groupRule("finance", "allow", "finance")))
	dst := address(b, "tcp", "203.0.113.2:443")
	var retained uint64
	for b.Loop() {
		sessions := make([]netapi.TrafficAccessSession, 1024)
		owners := make([]netapi.TrafficSubject, 1024)
		for i := range owners {
			owners[i] = subject(b.Context(), string(rune(i+1)), "finance")
		}
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		for i := range sessions {
			s, err := c.NewSession(owners[i], func(error) {})
			if err != nil {
				b.Fatal(err)
			}
			if err := s.Authorize(dst, dst); err != nil {
				b.Fatal(err)
			}
			sessions[i] = s
		}
		runtime.GC()
		runtime.ReadMemStats(&after)
		if after.HeapAlloc > before.HeapAlloc {
			retained += after.HeapAlloc - before.HeapAlloc
		}
		runtime.KeepAlive(sessions)
		for _, s := range sessions {
			s.Close()
		}
	}
	b.ReportMetric(float64(retained)/float64(b.N*1024), "heap-B/session")
}

func BenchmarkAccessUpdate1024(b *testing.B) {
	c := New()
	defer c.Close()
	cfg := config(groupRule("finance", "allow", "finance"))
	install(b, c, cfg)
	for i := range 1024 {
		s, err := c.NewSession(subject(b.Context(), string(rune(i+1)), "finance"), func(error) {})
		if err != nil {
			b.Fatal(err)
		}
		if err := s.Authorize(address(b, "udp", "203.0.113.2:443"), address(b, "udp", "203.0.113.2:443")); err != nil {
			b.Fatal(err)
		}
	}
	// Include compiling/publication and targeted revalidation, not SQL commit.
	b.ReportAllocs()
	for b.Loop() {
		p, err := Prepare(cfg)
		if err != nil {
			b.Fatal(err)
		}
		c.Activate(p)
	}
}

func BenchmarkAccessLargePolicy1024(b *testing.B) {
	c := New()
	defer c.Close()
	cfg := config()
	for i := range 1024 {
		cfg.Rules = append(cfg.Rules, groupRule(fmt.Sprintf("rule-%04d", i), "allow", fmt.Sprintf("group-%04d", i)))
	}
	install(b, c, cfg)
	groups := make([]string, 64)
	for i := range 63 {
		groups[i] = fmt.Sprintf("other-%04d", i)
	}
	groups[63] = "group-1023"
	slices.Sort(groups)
	owner := subject(b.Context(), "alice", groups...)
	dst := address(b, "udp", "203.0.113.2:443")
	b.ReportAllocs()
	for b.Loop() {
		if err := c.Check(owner, dst, dst); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAccessUpdateUnderTraffic1024(b *testing.B) {
	c := New()
	defer c.Close()
	cfg := config(groupRule("finance", "allow", "finance"))
	install(b, c, cfg)
	dst := address(b, "udp", "203.0.113.2:443")
	sessions := make([]netapi.TrafficAccessSession, 1024)
	for i := range sessions {
		s, err := c.NewSession(subject(b.Context(), fmt.Sprint(i), "finance"), func(error) {})
		if err != nil {
			b.Fatal(err)
		}
		if err := s.Authorize(dst, dst); err != nil {
			b.Fatal(err)
		}
		sessions[i] = s
	}
	var stop atomic.Bool
	var checks atomic.Uint64
	var failed atomic.Bool
	var workers sync.WaitGroup
	for worker := range 4 {
		workers.Go(func() {
			var count uint64
			defer func() { checks.Add(count) }()
			for !stop.Load() {
				for i := worker; i < len(sessions); i += 4 {
					if err := sessions[i].Authorize(dst, dst); err != nil {
						failed.Store(true)
					}
					count++
				}
			}
		})
	}
	b.ReportAllocs()
	for b.Loop() {
		p, err := Prepare(cfg)
		if err != nil {
			b.Fatal(err)
		}
		c.Activate(p)
	}
	stop.Store(true)
	workers.Wait()
	if failed.Load() {
		b.Fatal("allowed session rejected during publication")
	}
	b.ReportMetric(float64(checks.Load())/b.Elapsed().Seconds(), "concurrent-checks/s")
}
