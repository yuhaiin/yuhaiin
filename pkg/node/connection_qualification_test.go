package node

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type qualificationProxy struct{ netapi.Proxy }

func (qualificationProxy) Conn(context.Context, netapi.Address) (net.Conn, error) {
	return qualificationConn{}, nil
}
func (qualificationProxy) PacketConn(context.Context, netapi.Address) (net.PacketConn, error) {
	return new(udpCircuitPacket), nil
}
func (qualificationProxy) Close() error { return nil }

type qualificationConn struct{ net.Conn }

func (qualificationConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (qualificationConn) Write(b []byte) (int, error) { return len(b), nil }
func (qualificationConn) Close() error                { return nil }

func qualificationSelector(tb testing.TB, mode string) (*NodeRuntime, contract.Selector) {
	tb.Helper()
	r := NewNodeRuntime(tb.TempDir() + "/state.db")
	tb.Cleanup(func() {
		if err := r.Close(); err != nil {
			tb.Error(err)
		}
	})
	candidates := []contract.SelectorCandidate{}
	for _, id := range []string{"a", "b"} {
		n := contract.Node{ID: id, Name: id, Enabled: true, Chain: []contract.Protocol{{Type: "direct", Direct: &contract.Direct{}}}}
		if _, err := r.Save(tb.Context(), n); err != nil {
			tb.Fatal(err)
		}
		for _, tcp := range []bool{true, false} {
			r.observer.counter(id).remoteEvidence(tcp, contract.HealthSample{Kind: "reply", OK: true}, nil)
		}
		candidates = append(candidates, contract.SelectorCandidate{NodeID: id, Enabled: true, Weight: 1})
		if _, err := r.proxies.LoadOrCreate(tb.Context(), id, func() (*ProxyEntry, error) { return &ProxyEntry{Proxy: qualificationProxy{}, Name: id}, nil }); err != nil {
			tb.Fatal(err)
		}
	}
	s, err := NewSelectorService(r).Save(tb.Context(), contract.Selector{Name: "Qualification", NodeID: "a", Policy: &contract.SelectorPolicy{Mode: mode, Fallback: "priority_unknown", Candidates: candidates}})
	if err != nil {
		tb.Fatal(err)
	}
	return r, s
}

// A thousand readers perform new TCP/UDP admissions while persisted selector
// changes and high-rate health events replace the compiled immutable snapshots.
func TestSelector1024ConcurrentConnectionsDuringConfigAndHealthChurn(t *testing.T) {
	r, s := qualificationSelector(t, "weighted")
	target := contractroute.Target{Type: "selector", ID: s.ID}
	p, err := r.GetTarget(t.Context(), "tcp", "proxy", target)
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := netapi.ParseAddress("tcp", "example.invalid:443")
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, 1025)
	for range 1024 {
		wg.Go(func() {
			<-start
			ctx := netapi.WithContext(t.Context())
			for range 4 {
				conn, err := p.Conn(ctx, addr)
				if err != nil {
					errs <- err
					return
				}
				if _, err := conn.Write([]byte("one attempt")); err != nil {
					errs <- err
				}
				_ = conn.Close()
				packet, err := p.PacketConn(ctx, addr)
				if err != nil {
					errs <- err
					return
				}
				_ = packet.Close()
			}
		})
	}
	wg.Go(func() {
		<-start
		for i := range 12 {
			for _, id := range []string{"a", "b"} {
				r.observer.counter(id).remoteEvidence(true, contract.HealthSample{Kind: "connect", OK: true}, nil)
			}
			s.Name = fmt.Sprintf("Revision %d", i)
			next, err := NewSelectorService(r).Save(t.Context(), s)
			if err != nil {
				errs <- err
				return
			}
			s = next
		}
	})
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	for _, id := range []string{"a", "b"} {
		c := r.observer.counter(id)
		if c.activeTCP.Load() != 0 || c.activeUDP.Load() != 0 {
			t.Fatal("leaked active sessions", id)
		}
	}
}

// These benchmarks include the complete observed connection/session creation
// path with a deterministic in-memory transport, isolating selector overhead.
func BenchmarkSelectorConnectionCreation(b *testing.B) {
	for _, mode := range []string{"manual", "failover", "weighted"} {
		for _, network := range []string{"tcp", "udp"} {
			b.Run(mode+"/"+network, func(b *testing.B) {
				r, s := qualificationSelector(b, mode)
				p, err := r.GetTarget(b.Context(), network, "proxy", contractroute.Target{Type: "selector", ID: s.ID})
				if err != nil {
					b.Fatal(err)
				}
				ctx := netapi.WithContext(b.Context())
				addr, _ := netapi.ParseAddress(network, "example.invalid:443")
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					if network == "tcp" {
						c, err := p.Conn(ctx, addr)
						if err != nil {
							b.Fatal(err)
						}
						_ = c.Close()
					} else {
						c, err := p.PacketConn(ctx, addr)
						if err != nil {
							b.Fatal(err)
						}
						_ = c.Close()
					}
				}
			})
		}
	}
}

func BenchmarkSelectorLoopbackConnection(b *testing.B) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer listener.Close()
	var accepted sync.WaitGroup
	accepted.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	})
	defer accepted.Wait()
	// Defer order matters: stop Accept before waiting for its worker.
	defer listener.Close()
	for _, mode := range []string{"manual", "failover"} {
		b.Run(mode, func(b *testing.B) {
			r, s := qualificationSelector(b, mode)
			// Use the actual direct transport rather than the controlled in-memory one.
			r.proxies.Delete("a")
			r.proxies.Delete("b")
			p, err := r.GetTarget(b.Context(), "tcp", "proxy", contractroute.Target{Type: "selector", ID: s.ID})
			if err != nil {
				b.Fatal(err)
			}
			addr, _ := netapi.ParseAddress("tcp", listener.Addr().String())
			ctx, cancel := context.WithTimeout(b.Context(), time.Minute)
			defer cancel()
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				c, err := p.Conn(ctx, addr)
				if err != nil && !errors.Is(err, net.ErrClosed) {
					b.Fatal(err)
				}
				if c != nil {
					_ = c.Close()
				}
			}
		})
	}
}

func TestSelectorConnectionPathDoesNotQuerySQLite(t *testing.T) {
	r, s := qualificationSelector(t, "failover")
	target := contractroute.Target{Type: "selector", ID: s.ID}
	db := r.sqlite.DB()
	db.SetMaxOpenConns(1)
	held, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	addr, _ := netapi.ParseAddress("tcp", "example.invalid:443")
	for range 100 {
		if _, err := r.GetDialerByID(ctx, "a"); err != nil {
			t.Fatal("node dialer queried SQLite", err)
		}
		p, err := r.GetTarget(ctx, "tcp", "proxy", target)
		if err != nil {
			t.Fatal("selector queried SQLite", err)
		}
		c, err := p.Conn(ctx, addr)
		if err != nil {
			t.Fatal("new TCP connection queried SQLite", err)
		}
		_ = c.Close()
		packet, err := p.PacketConn(ctx, addr)
		if err != nil {
			t.Fatal("new UDP session queried SQLite", err)
		}
		_ = packet.Close()
	}
}

// New-flow includes GetTarget on every connection, matching the routing entry
// path; the cached-proxy benchmark above intentionally isolates that scenario.
func BenchmarkSelectorNewFlow(b *testing.B) {
	for _, mode := range []string{"manual", "failover", "weighted"} {
		for _, network := range []string{"tcp", "udp"} {
			b.Run(mode+"/"+network, func(b *testing.B) {
				r, s := qualificationSelector(b, mode)
				target := contractroute.Target{Type: "selector", ID: s.ID}
				addr, _ := netapi.ParseAddress(network, "example.invalid:443")
				ctx := netapi.WithContext(b.Context())
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					p, err := r.GetTarget(ctx, network, "proxy", target)
					if err != nil {
						b.Fatal(err)
					}
					if network == "tcp" {
						c, err := p.Conn(ctx, addr)
						if err != nil {
							b.Fatal(err)
						}
						_ = c.Close()
					} else {
						c, err := p.PacketConn(ctx, addr)
						if err != nil {
							b.Fatal(err)
						}
						_ = c.Close()
					}
				}
			})
		}
	}
}
