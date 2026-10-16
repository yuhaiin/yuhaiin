package tailscale

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"tailscale.com/ipn/ipnstate"
)

func TestPingCallback(t *testing.T) {
	for _, tt := range []struct {
		name    string
		result  *ipnstate.PingResult
		want    uint64
		wantErr bool
	}{
		{"success", &ipnstate.PingResult{LatencySeconds: 0.012345}, 12345000, false},
		{"error", &ipnstate.PingResult{Err: "no matching peer"}, 0, true},
		{"nil", nil, 0, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := awaitPing(t.Context(), func(cb func(*ipnstate.PingResult)) { go cb(tt.result) })
			if got != tt.want || (err != nil) != tt.wantErr {
				t.Fatalf("got %d %v", got, err)
			}
		})
	}
}
func TestPingCancellation(t *testing.T) {
	for _, cancelFirst := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
		if cancelFirst {
			cancel()
		}
		defer cancel()
		var callback func(*ipnstate.PingResult)
		_, err := awaitPing(ctx, func(cb func(*ipnstate.PingResult)) { callback = cb })
		want := error(context.DeadlineExceeded)
		if cancelFirst {
			want = context.Canceled
		}
		if !errors.Is(err, want) {
			t.Fatalf("got %v want %v", err, want)
		}
		if callback != nil {
			callback(&ipnstate.PingResult{})
			callback(&ipnstate.PingResult{})
		}
	}
}
func TestInstanceOwnership(t *testing.T) {
	c := Config{AuthKey: "secret", Hostname: "../../private", ControlURL: "https://control.example"}
	p1, err := New(c, direct.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer p1.Close()
	p2, err := New(c, direct.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	if p1 == p2 {
		t.Fatal("independent lifetimes share an outbound")
	}
	first := statePath(t.TempDir(), c)
	if strings.Contains(first, "secret") || strings.Contains(first, "private") {
		t.Fatal("secret or hostname leaked in state path")
	}
	c.ControlURL = "https://other.example"
	if statePath("base", c) == statePath("base", Config{AuthKey: "secret", Hostname: "../../private", ControlURL: "https://control.example"}) {
		t.Fatal("different controls share state")
	}
	_ = p1.Close()
	_, err = p1.(*Tailscale).init(t.Context())
	if !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

type recordingProxy struct {
	netapi.Proxy
	mu       sync.Mutex
	tcp, udp int
}

func (p *recordingProxy) Conn(ctx context.Context, a netapi.Address) (net.Conn, error) {
	p.mu.Lock()
	p.tcp++
	p.mu.Unlock()
	var d net.Dialer
	return d.DialContext(ctx, "tcp", a.String())
}
func (p *recordingProxy) PacketConn(ctx context.Context, a netapi.Address) (net.PacketConn, error) {
	p.mu.Lock()
	p.udp++
	p.mu.Unlock()
	var lc net.ListenConfig
	return lc.ListenPacket(ctx, a.Network(), netapi.GetContext(ctx).ConnOptions().BindAddress())
}

func TestUnderlayPerNodeAndRebind(t *testing.T) {
	for range 2 {
		proxy := &recordingProxy{Proxy: direct.Default}
		obj, err := New(Config{AuthKey: "test", Hostname: "node"}, proxy)
		if err != nil {
			t.Fatal(err)
		}
		defer obj.Close()
		owner := obj.(*Tailscale)
		u := &underlay{owner: owner, ancestors: []*Tailscale{owner}}
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			c, err := ln.Accept()
			if err == nil {
				_ = c.Close()
			}
		}()
		c, err := u.dialContext(t.Context(), "tcp4", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
		for _, network := range []string{"udp4", "udp6"} {
			bind := "127.0.0.1:0"
			if network == "udp6" {
				bind = "[::1]:0"
			}
			for range 2 {
				pc, err := u.ListenPacket(t.Context(), network, bind)
				if err != nil {
					t.Fatal(err)
				}
				endpoint := pc.LocalAddr().(*net.UDPAddr).AddrPort()
				if endpoint.Port() == 0 {
					t.Fatal("unallocated local port")
				}
				_ = pc.SetDeadline(time.Now().Add(time.Second))
				if _, err := pc.WriteToUDPAddrPort([]byte("echo"), endpoint); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 16)
				n, from, err := pc.ReadFromUDPAddrPort(buf)
				if err != nil {
					t.Fatal(err)
				}
				if string(buf[:n]) != "echo" || from != endpoint {
					t.Fatalf("payload/source: %q %v", buf[:n], from)
				}
				_ = pc.SetReadDeadline(time.Now().Add(-time.Second))
				if _, _, err := pc.ReadFromUDPAddrPort(buf); err == nil {
					t.Fatal("deadline not honored")
				}
				_ = pc.Close()
				if _, _, err := pc.ReadFromUDPAddrPort(buf); err == nil {
					t.Fatal("closed socket readable")
				}
			}
		}
		proxy.mu.Lock()
		tcp, udp := proxy.tcp, proxy.udp
		proxy.mu.Unlock()
		if tcp != 1 || udp != 4 {
			t.Fatalf("calls tcp=%d udp=%d", tcp, udp)
		}
	}
}
func TestUnderlayLoop(t *testing.T) {
	obj, err := New(Config{AuthKey: "test"}, direct.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer obj.Close()
	owner := obj.(*Tailscale)
	u := &underlay{owner: owner, ancestors: []*Tailscale{owner}}
	ctx, err := u.context(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := checkLoop(ctx, owner); err == nil {
		t.Fatal("loop not detected")
	}
	// Calling through the actual upstream must also reject recursive use before
	// waiting on initialization, including a background tsnet dialing context.
	owner.dialer = owner
	_, err = u.dialContext(t.Context(), "tcp", "127.0.0.1:1")
	if err == nil || !strings.Contains(err.Error(), "recursive") {
		t.Fatal(err)
	}
}

func TestServiceDNSAddress(t *testing.T) {
	for _, ip := range []string{"100.100.100.100", "fd7a:115c:a1e0::53"} {
		if !isServiceDNS(netapi.ParseNetipAddr("udp", netip.MustParseAddr(ip), 53)) {
			t.Fatal(ip)
		}
	}
	if isServiceDNS(netapi.ParseNetipAddr("udp", netip.MustParseAddr("8.8.8.8"), 53)) {
		t.Fatal("intercepted ordinary DNS")
	}
}

func TestStateMigration(t *testing.T) {
	for _, hostname := range []string{"existing", ""} {
		t.Run(hostname, func(t *testing.T) {
			base := t.TempDir()
			old := filepath.Join(base, "tailscale", hostname)
			if err := os.MkdirAll(old, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(old, "tailscaled.state"), []byte("identity"), 0600); err != nil {
				t.Fatal(err)
			}
			dir := statePath(base, Config{Hostname: hostname, AuthKey: "secret"})
			if err := migrateState(base, dir, hostname); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(filepath.Join(dir, "tailscaled.state"))
			if err != nil || string(b) != "identity" {
				t.Fatalf("state %q %v", b, err)
			}
			if err := migrateState(base, dir, hostname); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUnderlayCycleAcrossBackgroundContexts(t *testing.T) {
	aProxy, _ := New(Config{AuthKey: "a"}, direct.Default)
	a := aProxy.(*Tailscale)
	defer a.Close()
	bProxy, _ := New(Config{AuthKey: "b"}, direct.Default)
	b := bProxy.(*Tailscale)
	defer b.Close()
	cProxy, _ := New(Config{AuthKey: "c"}, direct.Default)
	c := cProxy.(*Tailscale)
	defer c.Close()
	aCtx := context.WithValue(t.Context(), loopKey{}, []*Tailscale{a})
	bCtx := context.WithValue(t.Context(), loopKey{}, []*Tailscale{b})
	cCtx := context.WithValue(t.Context(), loopKey{}, []*Tailscale{c})
	if err := checkLoop(aCtx, b); err != nil {
		t.Fatal(err)
	}
	if err := checkLoop(bCtx, c); err != nil {
		t.Fatal(err)
	}
	if err := checkLoop(cCtx, a); err == nil {
		t.Fatal("A -> B -> C -> A cycle escaped across background contexts")
	}
	forgetUnderlay(b)
	if err := checkLoop(cCtx, a); err != nil {
		t.Fatalf("closed dependency was retained: %v", err)
	}
}

func TestUnderlayAddressFamilies(t *testing.T) {
	proxy := &recordingProxy{Proxy: direct.Default}
	obj, _ := New(Config{AuthKey: "test"}, proxy)
	defer obj.Close()
	owner := obj.(*Tailscale)
	u := &underlay{owner: owner, ancestors: []*Tailscale{owner}}
	for _, network := range []string{"udp4", "udp6"} {
		pc, err := u.ListenPacket(t.Context(), network, ":0")
		if err != nil {
			t.Fatal(err)
		}
		ip := pc.LocalAddr().(*net.UDPAddr).IP
		if (ip.To4() != nil) != (network == "udp4") {
			t.Fatalf("%s bound %v", network, pc.LocalAddr())
		}
		_ = pc.Close()
	}
	for _, tt := range []struct{ network, address string }{{"tcp4", "[::1]:1"}, {"tcp6", "127.0.0.1:1"}} {
		if _, err := u.dialContext(t.Context(), tt.network, tt.address); err == nil {
			t.Fatal("mismatched family accepted")
		}
	}
	proxy.mu.Lock()
	tcp := proxy.tcp
	proxy.mu.Unlock()
	if tcp != 0 {
		t.Fatal("invalid family reached upstream")
	}
}
