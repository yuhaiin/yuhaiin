package hysteria2

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	node "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type happyEyeballsTestConn struct {
	closed atomic.Bool
}

func (c *happyEyeballsTestConn) Close() error {
	c.closed.Store(true)
	return nil
}

func TestRaceUDPAddressesClosesLateWinner(t *testing.T) {
	slow := &happyEyeballsTestConn{}
	fast := &happyEyeballsTestConn{}
	lateClosed := make(chan struct{})
	targets := []*net.UDPAddr{
		{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		{IP: net.IPv4(127, 0, 0, 1), Port: 2},
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	conn, remote, err := raceUDPAddresses(ctx, targets, func(ctx context.Context, remote *net.UDPAddr) (*happyEyeballsTestConn, error) {
		if remote.Port == 2 {
			return fast, nil
		}
		<-ctx.Done()
		defer close(lateClosed)
		return slow, nil // An in-flight dial can finish after cancellation.
	})
	if err != nil {
		t.Fatal(err)
	}
	if conn != fast || remote.Port != 2 {
		t.Fatalf("wrong winner: %v, %v", conn, remote)
	}
	select {
	case <-lateClosed:
	case <-time.After(time.Second):
		t.Fatal("losing dial was not canceled")
	}
	if !slow.closed.Load() {
		t.Fatal("late successful connection leaked")
	}
	if fast.closed.Load() {
		t.Fatal("winning connection was closed")
	}
	_ = conn.Close()
}

func TestRaceUDPAddressesAllFail(t *testing.T) {
	targets := []*net.UDPAddr{
		{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		{IP: net.IPv4(127, 0, 0, 1), Port: 2},
	}
	_, _, err := raceUDPAddresses(t.Context(), targets, func(context.Context, *net.UDPAddr) (*happyEyeballsTestConn, error) {
		return nil, errors.New("unreachable")
	})
	if err == nil || strings.Count(err.Error(), "unreachable") != 2 {
		t.Fatalf("lost individual dial errors: %v", err)
	}
}

func TestHysteria2HappyEyeballsChoosesReachableRelay(t *testing.T) {
	backend, ca, _, handler := newTestServer(t, "")
	relay := newAddressTestRelay(t, "127.0.0.2:0", backend)
	blackhole, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	tracker := &addressTestDialer{}
	config := node.Hysteria2{
		Host:          blackhole.LocalAddr().String(),
		HopAddresses:  []string{relay.front.LocalAddr().String()},
		HappyEyeballs: true,
		Auth:          "secret",
		TLS:           node.TLS{CACert: [][]byte{ca}, ServerNames: []string{"test.example"}},
	}
	proxy, err := NewClient(config, tracker)
	if err != nil {
		t.Fatal(err)
	}
	client := proxy.(*Client)
	defer client.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 7*time.Second)
	defer cancel()
	target, _ := netapi.ParseAddress("tcp", "example.com:443")
	stream, err := client.Conn(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	select {
	case <-handler.streams:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if client.preferred == nil || client.preferred.String() != relay.front.LocalAddr().String() {
		t.Fatalf("selected %v, want %v", client.preferred, relay.front.LocalAddr())
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for tracker.closed.Load() != tracker.opened.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if tracker.opened.Load() < 2 || tracker.opened.Load() != tracker.closed.Load() {
		t.Fatalf("socket leak: opened=%d closed=%d", tracker.opened.Load(), tracker.closed.Load())
	}
}

func TestHysteria2HappyEyeballsDefaultDualStack(t *testing.T) {
	backend, ca, _, _ := newTestServer(t, "")
	relay := newAddressTestRelay(t, "127.0.0.2:0", backend)
	_, port, err := net.SplitHostPort(relay.front.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	var dnsCalls atomic.Int32
	resolverCtx := netapi.WithContext(t.Context())
	resolverCtx.ConnOptions().Resolver().SetResolver(&addressHopTestResolver{
		lookup: func(context.Context, string) (*netapi.IPs, error) {
			dnsCalls.Add(1)
			return &netapi.IPs{
				A:    []net.IP{net.ParseIP("127.0.0.2")},
				AAAA: []net.IP{net.ParseIP("::1")},
			}, nil
		},
	})
	proxy, err := NewClient(node.Hysteria2{
		Host: net.JoinHostPort("dual.example", port),
		Auth: "secret",
		TLS:  node.TLS{CACert: [][]byte{ca}, ServerNames: []string{"test.example"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	ctx, cancel := context.WithTimeout(resolverCtx, 7*time.Second)
	defer cancel()
	target, _ := netapi.ParseAddress("tcp", "example.com:443")
	stream, err := proxy.Conn(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	client := proxy.(*Client)
	if client.preferred == nil || client.preferred.IP.To4() == nil {
		t.Fatalf("did not fall back to IPv4: %v", client.preferred)
	}
	if dnsCalls.Load() != 2 {
		t.Fatalf("DNS lookups = %d, want two family queries", dnsCalls.Load())
	}
}

func TestHappyEyeballsv2PrefersIPv6AfterQuickAAAA(t *testing.T) {
	batches := make(chan happyEyeballsBatch, 2)
	go func() {
		batches <- happyEyeballsBatch{addrs: []*net.UDPAddr{{IP: net.IPv4(127, 0, 0, 1), Port: 443}}}
		time.Sleep(10 * time.Millisecond)
		batches <- happyEyeballsBatch{addrs: []*net.UDPAddr{{IP: net.ParseIP("::1"), Port: 443}}}
		close(batches)
	}()
	conn, addr, err := raceHappyEyeballsv2(t.Context(), batches, nil, false, func(context.Context, *net.UDPAddr) (*happyEyeballsTestConn, error) {
		return &happyEyeballsTestConn{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if addr.IP.To4() != nil {
		t.Fatalf("IPv4 won before 50ms resolution delay: %s", addr)
	}
}

type slowAAAAResolver struct {
	netapi.Resolver
	started chan struct{}
}

func (r *slowAAAAResolver) LookupIP(ctx context.Context, _ string, opts ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	var option netapi.LookupIPOption
	for _, opt := range opts {
		opt(&option)
	}
	if option.Mode == netapi.ResolverModePreferIPv6 {
		close(r.started)
		<-ctx.Done() // AAAA can hang; IPv4 must not wait for it.
		return nil, ctx.Err()
	}
	return &netapi.IPs{A: []net.IP{net.ParseIP("127.0.0.2")}}, nil
}

func TestHysteria2HappyEyeballsv2DoesNotWaitForAAAA(t *testing.T) {
	backend, ca, _, _ := newTestServer(t, "")
	relay := newAddressTestRelay(t, "127.0.0.2:0", backend)
	_, port, err := net.SplitHostPort(relay.front.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	resolver := &slowAAAAResolver{started: make(chan struct{})}
	setupCtx := netapi.WithContext(t.Context())
	setupCtx.ConnOptions().Resolver().SetResolver(resolver)
	proxy, err := NewClient(node.Hysteria2{
		Host: net.JoinHostPort("dual.example", port),
		Auth: "secret",
		TLS:  node.TLS{CACert: [][]byte{ca}, ServerNames: []string{"test.example"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	ctx, cancel := context.WithTimeout(setupCtx, 5*time.Second)
	defer cancel()
	target, _ := netapi.ParseAddress("tcp", "example.com:443")
	stream, err := proxy.Conn(ctx, target)
	if err != nil {
		t.Fatalf("IPv4 was blocked by AAAA query: %v", err)
	}
	defer stream.Close()
	select {
	case <-resolver.started:
	default:
		t.Fatal("AAAA query was not started concurrently")
	}
}
