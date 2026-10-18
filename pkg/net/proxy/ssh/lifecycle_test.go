package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	gossh "golang.org/x/crypto/ssh"
)

func testTarget(t testing.TB) netapi.Address {
	t.Helper()
	dst, err := netapi.ParseAddress("tcp", "remote-only.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func newTestClient(t testing.TB, addr, pin string) *Client {
	t.Helper()
	p, err := NewClient(configForTest(pin), &testUpstream{addr: addr})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p.(*Client)
}

// A blocked pipe makes the first SSH version exchange deterministic, without
// relying on a remote service, packet loss, or the 15-second handshake timeout.
type stalledUpstream struct {
	*testUpstream
	raw     net.Conn
	entered chan struct{}
	once    sync.Once
}

func (p *stalledUpstream) Conn(context.Context, netapi.Address) (net.Conn, error) {
	p.once.Do(func() { close(p.entered) })
	return p.raw, nil
}

func startStalledHandshake(t *testing.T) (*Client, context.CancelFunc, <-chan struct{}) {
	t.Helper()
	raw, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	upstream := &stalledUpstream{testUpstream: &testUpstream{}, raw: raw, entered: make(chan struct{})}
	p, err := NewClient(configForTest("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), upstream)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	finished := make(chan struct{})
	go func() { defer close(finished); _, _ = p.Conn(ctx, testTarget(t)) }()
	<-upstream.entered
	t.Cleanup(func() { cancel(); <-finished; _ = p.Close() })
	return p.(*Client), cancel, finished
}

func TestSSHQueuedDialHonorsContext(t *testing.T) {
	p, cancelFirst, firstFinished := startStalledHandshake(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := p.Conn(ctx, testTarget(t)); result <- err }()
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("error = %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("30ms dial context still blocked after 200ms behind another handshake")
		cancelFirst()
		<-firstFinished
		if err := <-result; err == nil {
			t.Error("queued dial unexpectedly succeeded")
		}
	}
}

func TestSSHCloseInterruptsHandshake(t *testing.T) {
	p, cancelFirst, firstFinished := startStalledHandshake(t)
	closed := make(chan struct{})
	go func() { _ = p.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(200 * time.Millisecond):
		t.Error("Close cannot interrupt an in-flight SSH handshake")
		cancelFirst()
		<-firstFinished
		<-closed
	}
}

func TestSSHChannelDeadline(t *testing.T) {
	addr, pin, _ := startSSHServer(t)
	p := newTestClient(t, addr, pin)
	conn, err := p.Conn(t.Context(), testTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatalf("net.Conn deadline contract: %v", err)
	}
	result := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 1)); result <- err }()
	select {
	case err := <-result:
		ne, ok := errors.AsType[net.Error](err)
		if !ok || !ne.Timeout() {
			t.Errorf("expected timeout, got %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		_ = conn.Close()
		if err := <-result; err == nil {
			t.Error("read unexpectedly succeeded after close")
		}
		t.Fatal("read deadline did not interrupt channel read")
	}
}

func TestSSHDNSOverTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var size uint16
				if err := binary.Read(conn, binary.BigEndian, &size); err != nil {
					return
				}
				request := &dns.Msg{Data: make([]byte, size)}
				if _, err := io.ReadFull(conn, request.Data); err != nil {
					return
				}
				if err := request.Unpack(); err != nil || len(request.Question) != 1 {
					return
				}
				response := &dns.Msg{ID: request.ID, Response: true, Question: request.Question,
					Answer: []dns.RR{&dns.A{Hdr: dns.Header{Name: request.Question[0].Header().Name, Class: dns.ClassINET, TTL: 60}, Addr: netip.MustParseAddr("192.0.2.1")}}}
				if err := response.Pack(); err != nil {
					return
				}
				if err := binary.Write(conn, binary.BigEndian, uint16(len(response.Data))); err != nil {
					return
				}
				_, _ = conn.Write(response.Data)
			}()
		}
	}()
	_, host := newTestSigner(t)
	_, auth := newTestSigner(t)
	addr, _ := startForwardingSSHServer(t, []gossh.Signer{host}, auth.PublicKey(), ln.Addr().String())
	p := newTestClient(t, addr, gossh.FingerprintSHA256(host.PublicKey()))
	transport, err := resolver.New(resolver.Config{Type: "tcp", Host: "remote-only.invalid:53", Dialer: p})
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	ips, err := transport.LookupIP(ctx, "deadline-check.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if ips == nil || ips.Len() == 0 {
		t.Fatal("DNS-over-TCP returned no addresses")
	}
}

func TestSSHNesting(t *testing.T) {
	innerAddress, innerPin, _ := startSSHServer(t)
	_, host := newTestSigner(t)
	_, auth := newTestSigner(t)
	addr, _ := startForwardingSSHServer(t, []gossh.Signer{host}, auth.PublicKey(), innerAddress)
	outer := newTestClient(t, addr, gossh.FingerprintSHA256(host.PublicKey()))
	innerProxy, err := NewClient(configForTest(innerPin), outer)
	if err != nil {
		t.Fatal(err)
	}
	defer innerProxy.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	conn, err := innerProxy.Conn(ctx, testTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("nested")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 6)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "nested" {
		t.Fatalf("nested echo = %q", got)
	}
}

func TestSSHParallelChannels(t *testing.T) {
	addr, pin, accepted := startSSHServer(t)
	p := newTestClient(t, addr, pin)
	dst := testTarget(t)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			conn, err := p.Conn(ctx, dst)
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			message := []byte("multiplexed data")
			if _, err := conn.Write(message); err != nil {
				t.Error(err)
				return
			}
			got := make([]byte, len(message))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Error(err)
				return
			}
			if string(got) != string(message) {
				t.Errorf("echo = %q", got)
			}
		})
	}
	wg.Wait()
	if got := accepted.Load(); got != 1 {
		t.Errorf("SSH transports = %d; want 1", got)
	}
}

func TestSSHReconnectAfterDisconnect(t *testing.T) {
	addr, pin, accepted := startSSHServer(t)
	p := newTestClient(t, addr, pin)
	conn, err := p.Conn(t.Context(), testTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	p.mu.Lock()
	old, done := p.client, p.done
	p.mu.Unlock()
	_ = old.Close()
	<-done
	// watch closes done before clearing c.client. Observe automatic cleanup
	// without manually invalidating the cached client in this test.
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	for {
		p.mu.Lock()
		cleared := p.client == nil
		p.mu.Unlock()
		if cleared {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("watcher did not clear disconnected transport")
		case <-time.After(time.Millisecond):
		}
	}
	conn, err = p.Conn(t.Context(), testTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if got := accepted.Load(); got != 2 {
		t.Fatalf("SSH transports = %d; want 2", got)
	}
}

func TestSSHCloseStopsChannels(t *testing.T) {
	addr, pin, _ := startSSHServer(t)
	p := newTestClient(t, addr, pin)
	conn, err := p.Conn(t.Context(), testTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("channel remained readable after proxy Close")
	}
	if _, err := p.Conn(t.Context(), testTarget(t)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Conn after Close = %v; want net.ErrClosed", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestSSHKeepAliveDetectsSilentPeer(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	config := &gossh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	probe := make(chan struct{})
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		conn, channels, requests, err := gossh.NewServerConn(raw, config)
		if err != nil {
			_ = raw.Close()
			return
		}
		defer conn.Close()
		go func() {
			for req := range requests {
				if req.Type == "keepalive@openssh.com" {
					close(probe)
					return
				}
			}
		}()
		for ch := range channels {
			channel, reqs, err := ch.Accept()
			if err != nil {
				continue
			}
			go gossh.DiscardRequests(reqs)
			_ = channel.Close()
		}
	}()
	cfg := configForTest(gossh.FingerprintSHA256(signer.PublicKey()))
	cfg.KeepAliveSeconds = 1
	proxy, err := NewClient(cfg, &testUpstream{addr: ln.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	p := proxy.(*Client)
	conn, err := p.Conn(t.Context(), testTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	select {
	case <-probe:
	case <-time.After(3 * time.Second):
		t.Fatal("no keepalive probe")
	}
	p.mu.Lock()
	done := p.done
	p.mu.Unlock()
	select {
	case <-done:
	case <-time.After(2200 * time.Millisecond):
		t.Fatal("unanswered keepalive did not invalidate transport after >2 intervals; SendRequest has no response deadline")
	}
}
