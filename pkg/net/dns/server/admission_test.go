package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

func TestDNSCachedBypassesSaturatedQueries(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "stale"}[stale], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				agent, upstream := admissionServer(t, 1, resolver.TransportFunc(func(ctx context.Context, req *resolver.Request) (*dns.Msg, error) {
					if req.Question.Name == "cached.example." {
						return admissionAnswer(req, 2), nil
					}
					<-ctx.Done()
					return nil, ctx.Err()
				}))
				if _, err := upstream.Raw(t.Context(), netapi.DNSQuestion{Name: "cached.example.", Qtype: dns.TypeA}); err != nil {
					t.Fatal(err)
				}
				if stale {
					time.Sleep(3 * time.Second)
				}
				admissionEnqueue(t, agent, t.Context(), admissionQuery(t, "slow.example."))
				synctest.Wait()
				admissionEnqueue(t, agent, t.Context(), admissionQuery(t, "queued.example."))
				synctest.Wait()
				done := admissionEnqueue(t, agent, t.Context(), admissionQuery(t, "cached.example."))
				synctest.Wait()
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				default:
					t.Fatal("cached answer waited behind slow upstream queries")
				}
				_ = agent.Close()
				synctest.Wait()
			})
		})
	}
}
func TestDNSQueuedRequestPreservesCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		agent, _ := admissionServer(t, 1, resolver.TransportFunc(func(ctx context.Context, _ *resolver.Request) (*dns.Msg, error) {
			calls.Add(1)
			<-ctx.Done()
			return nil, ctx.Err()
		}))
		admissionEnqueue(t, agent, t.Context(), admissionQuery(t, "slow.example."))
		synctest.Wait()
		ctx, cancel := context.WithCancel(t.Context())
		done := admissionEnqueue(t, agent, ctx, admissionQuery(t, "canceled.example."))
		synctest.Wait()
		cancel()
		synctest.Wait()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("completion=%v", err)
			}
		default:
			t.Error("accepted request ignored caller cancellation")
		}
		if calls.Load() != 1 {
			t.Fatalf("canceled request reached upstream: calls=%d", calls.Load())
		}
		_ = agent.Close()
		synctest.Wait()
	})
}
func TestDNSAdmissionDeadlineIncludesWaiting(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		agent, _ := admissionServer(t, 1, resolver.TransportFunc(func(ctx context.Context, _ *resolver.Request) (*dns.Msg, error) { <-ctx.Done(); return nil, ctx.Err() }))
		admissionEnqueue(t, agent, t.Context(), admissionQuery(t, "slow.example."))
		synctest.Wait()
		time.Sleep(6 * time.Second)
		done := admissionEnqueue(t, agent, t.Context(), admissionQuery(t, "waiting.example."))
		synctest.Wait()
		time.Sleep(configuration.ResolverTimeout)
		synctest.Wait()
		select {
		case err := <-done:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("completion=%v", err)
			}
		default:
			t.Error("query got a new timeout after waiting for admission")
		}
		_ = agent.Close()
		synctest.Wait()
	})
}
func TestDNSDuplicateWaitersDoNotConsumeQuerySlots(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		agent, _ := admissionServer(t, 2, resolver.TransportFunc(func(ctx context.Context, req *resolver.Request) (*dns.Msg, error) {
			if req.Question.Name == "slow.example." {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return admissionAnswer(req, 60), nil
		}))
		for range 12 {
			admissionEnqueue(t, agent, t.Context(), admissionQuery(t, "slow.example."))
			synctest.Wait()
		}
		done := admissionEnqueue(t, agent, t.Context(), admissionQuery(t, "independent.example."))
		synctest.Wait()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		default:
			t.Error("duplicate waiters consumed the independent query's permit")
		}
		_ = agent.Close()
		synctest.Wait()
	})
}

func TestDNSOverloadStillServesCacheAndCompletesOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		previous := configuration.MaxUDPUnprocessedPackets.Load()
		configuration.MaxUDPUnprocessedPackets.Store(2)
		defer configuration.MaxUDPUnprocessedPackets.Store(previous)
		var active, peak atomic.Int32
		agent, upstream := admissionServer(t, 1, resolver.TransportFunc(func(ctx context.Context, req *resolver.Request) (*dns.Msg, error) {
			if req.Question.Name == "cached.example." {
				return admissionAnswer(req, 60), nil
			}
			n := active.Add(1)
			defer active.Add(-1)
			if n > peak.Load() {
				peak.Store(n)
			}
			<-ctx.Done()
			return nil, ctx.Err()
		}))
		if _, err := upstream.Raw(t.Context(), netapi.DNSQuestion{Name: "cached.example.", Qtype: dns.TypeA}); err != nil {
			t.Fatal(err)
		}
		completions := make([]<-chan error, 0, 3)
		for i := range 3 {
			completions = append(completions, admissionEnqueue(t, agent, t.Context(), admissionQuery(t, fmt.Sprintf("slow-%d.example.", i))))
			synctest.Wait()
		}
		if got := agent.outstanding.Load(); got != 3 {
			t.Fatalf("outstanding=%d want 3", got)
		}
		packet := netapi.NewPacket(nil, nil, pool.Clone(admissionQuery(t, "overload.example.")), nil)
		called := false
		err := agent.DoDatagram(t.Context(), &netapi.DNSRawRequest{Question: packet, Done: func(error) { called = true }})
		packet.DecRef()
		if err == nil || called {
			t.Fatalf("overload admission=%v completion=%t", err, called)
		}
		cached := admissionEnqueue(t, agent, t.Context(), admissionQuery(t, "cached.example."))
		select {
		case err := <-cached:
			if err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatal("full miss budget blocked cached answer")
		}
		_ = agent.Close()
		synctest.Wait()
		for _, done := range completions {
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("close completion=%v", err)
				}
			default:
				t.Fatal("accepted request did not complete")
			}
			select {
			case err := <-done:
				t.Fatalf("duplicate completion %v", err)
			default:
			}
		}
		if agent.outstanding.Load() != 0 || active.Load() != 0 || peak.Load() != 1 {
			t.Fatalf("leaked/over-admitted work: outstanding=%d active=%d peak=%d", agent.outstanding.Load(), active.Load(), peak.Load())
		}
	})
}

func TestDNSStandaloneUDPCacheBypassesSlowQuery(t *testing.T) {
	started := make(chan struct{}, 1)
	agent, upstream := admissionServer(t, 1, resolver.TransportFunc(func(ctx context.Context, req *resolver.Request) (*dns.Msg, error) {
		if req.Question.Name == "slow.example." {
			started <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return admissionAnswer(req, 60), nil
	}))
	if _, err := upstream.Raw(t.Context(), netapi.DNSQuestion{Name: "cached.example.", Qtype: dns.TypeA}); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	agent.udp = listener
	agent.startUDP(listener)
	client, err := net.Dial("udp", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Write(admissionQuery(t, "slow.example.")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("slow query did not start")
	}
	if _, err := client.Write(admissionQuery(t, "cached.example.")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("cached UDP reply blocked: %v", err)
	}
	msg := &dns.Msg{Data: buf[:n]}
	if err := msg.Unpack(); err != nil {
		t.Fatal(err)
	}
	if len(msg.Question) != 1 || msg.Question[0].Header().Name != "cached.example." {
		t.Fatalf("unexpected reply: %v", msg)
	}
}

func TestDNSMissRetainsRequestRoutingContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		type key struct{}
		agent, _ := admissionServer(t, 1, resolver.TransportFunc(func(ctx context.Context, req *resolver.Request) (*dns.Msg, error) {
			if ctx.Value(key{}) != "caller" || netapi.GetContext(ctx).GetInboundID() != "entry-a" {
				t.Errorf("lost caller routing context")
			}
			return admissionAnswer(req, 60), nil
		}))
		ctx := netapi.WithContext(context.WithValue(t.Context(), key{}, "caller"))
		ctx.SetInboundID("entry-a")
		done := admissionEnqueue(t, agent, ctx, admissionQuery(t, "context.example."))
		synctest.Wait()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
}
