//go:build linux && !android

package processnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/yuhaiin/sessionnet"
)

const clientEnv = "YUH_PROCESSNET_LOOPBACK_CLIENT"

// TestHostLoopbackClientHelper runs inside a session (see spawnClient).
func TestHostLoopbackClientHelper(t *testing.T) {
	spec := os.Getenv(clientEnv)
	if spec == "" {
		t.Skip("in-session client")
	}
	kind, target, _ := strings.Cut(spec, "|")
	switch kind {
	case "udp":
		c, err := net.Dial("udp", target)
		if err != nil {
			fmt.Println("ERR", err)
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("hello"))
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		fmt.Printf("REPLY %s %v\n", buf[:n], err)
	case "tcpmany":
		var wg sync.WaitGroup
		var mu sync.Mutex
		ok := 0
		for i := range 200 {
			wg.Go(func() {
				c, err := net.DialTimeout("tcp", target, 5*time.Second)
				if err != nil {
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				msg := fmt.Sprintf("conn-%d", i)
				_, _ = c.Write([]byte(msg))
				_ = c.(*net.TCPConn).CloseWrite() // half-close: the host must still answer
				got, _ := io.ReadAll(c)
				if string(got) == "echo:"+msg {
					mu.Lock()
					ok++
					mu.Unlock()
				}
			})
		}
		wg.Wait()
		fmt.Printf("TCPOK %d\n", ok)
	}
}

func openForwardSession(t *testing.T, mappings []HostLoopbackMapping) *sessionnet.Session {
	t.Helper()
	// The session lives as long as its context.
	s, err := sessionnet.Open(t.Context(), sessionnet.Config{IPv6: true, LoopbackForwards: HostLoopbackForwards(mappings)})
	if err != nil {
		if os.Getenv("YUH_REQUIRE_ROOTLESS") == "1" {
			t.Fatal(err)
		}
		t.Skipf("isolated sessions are unavailable: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func spawnClient(t *testing.T, s *sessionnet.Session, spec string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var out strings.Builder
	var mu sync.Mutex
	w := writerFunc(func(b []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return out.Write(b) })
	p, err := s.Spawn(ctx, sessionnet.Config{Command: []string{os.Args[0], "-test.run=^TestHostLoopbackClientHelper$"},
		Env: []string{clientEnv + "=" + spec}, Stdout: w, Stderr: w})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Wait(); err != nil {
		t.Fatalf("client %s: %v\n%s", spec, err, out.String())
	}
	mu.Lock()
	defer mu.Unlock()
	return out.String()
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }

func udpEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

func tcpEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				data, _ := io.ReadAll(c)
				_, _ = c.Write(append([]byte("echo:"), data...))
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).AddrPort()
}

func TestHostLoopbackUDPIdleExpiryAndCleanup(t *testing.T) {
	savedIdle, savedReap := hostLoopbackUDPIdle, hostLoopbackUDPReap
	hostLoopbackUDPIdle, hostLoopbackUDPReap = 2*time.Second, 50*time.Millisecond
	t.Cleanup(func() { hostLoopbackUDPIdle, hostLoopbackUDPReap = savedIdle, savedReap })

	host := udpEcho(t)
	mappings := []HostLoopbackMapping{{Network: "udp", Session: netip.MustParseAddrPort("127.0.0.1:5353"), Host: host}}
	s := openForwardSession(t, mappings)
	goroutines := runtime.NumGoroutine()
	h, err := StartHostLoopback(s, mappings, nil, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Release(); err != nil {
		t.Fatal(err)
	}
	if out := spawnClient(t, s, "udp|127.0.0.1:5353"); !strings.Contains(out, "REPLY echo:hello <nil>") {
		t.Fatalf("UDP round trip: %s", out)
	}
	if n := h.udpFlows.Load(); n != 1 {
		t.Fatalf("%d UDP flows after one client", n)
	}
	deadline := time.Now().Add(6 * time.Second)
	for h.udpFlows.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := h.udpFlows.Load(); n != 0 {
		t.Fatalf("idle UDP flow was not expired (%d flows)", n)
	}
	// A new datagram after expiry opens a fresh flow.
	if out := spawnClient(t, s, "udp|127.0.0.1:5353"); !strings.Contains(out, "REPLY echo:hello <nil>") {
		t.Fatalf("UDP after expiry: %s", out)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal("Close must be idempotent:", err)
	}
	if n := h.udpFlows.Load(); n != 0 {
		t.Fatalf("%d UDP flows survived Close", n)
	}
	deadline = time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > goroutines && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > goroutines {
		t.Fatalf("%d goroutines leaked", n-goroutines)
	}
}

func TestHostLoopbackManyTCPConnections(t *testing.T) {
	host := tcpEcho(t)
	mappings := []HostLoopbackMapping{{Network: "tcp", Session: netip.MustParseAddrPort("[::1]:6379"), Host: host}}
	s := openForwardSession(t, mappings)
	fds := countFDs(t)
	h, err := StartHostLoopback(s, mappings, nil, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Release(); err != nil {
		t.Fatal(err)
	}
	if out := spawnClient(t, s, "tcpmany|[::1]:6379"); !strings.Contains(out, "TCPOK 200") {
		t.Fatalf("concurrent TCP connections: %s", out)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if after := countFDs(t); after > fds {
		t.Fatalf("%d descriptors leaked", after-fds)
	}
}

func TestStartHostLoopbackRejects(t *testing.T) {
	host := tcpEcho(t)
	reserved := []HostLoopbackMapping{{Network: "tcp", Session: netip.MustParseAddrPort("127.0.0.1:7000"), Host: host}}
	s := openForwardSession(t, reserved)
	// A mapping the session did not reserve cannot be served.
	other := []HostLoopbackMapping{{Network: "tcp", Session: netip.MustParseAddrPort("127.0.0.1:7001"), Host: host}}
	if _, err := StartHostLoopback(s, other, nil, nil, "test"); err == nil {
		t.Fatal("an unreserved mapping was accepted")
	}
	bad := []HostLoopbackMapping{{Network: "tcp", Session: netip.MustParseAddrPort("127.0.0.1:7000"), Host: netip.MustParseAddrPort("10.0.0.1:80")}}
	if _, err := StartHostLoopback(s, bad, nil, nil, "test"); err == nil {
		t.Fatal("a non-loopback host target was accepted")
	}
	// The reserved socket is still intact for a valid start afterwards.
	h, err := StartHostLoopback(s, reserved, nil, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	_ = h.Close()
}

func countFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func TestValidateHostLoopbackMappings(t *testing.T) {
	lo := netip.MustParseAddrPort
	good := []HostLoopbackMapping{
		{"tcp", lo("127.0.0.1:5432"), lo("127.0.0.1:5432")},
		{"tcp", lo("[::1]:5432"), lo("[::1]:5432")},
		{"tcp", lo("[::1]:8080"), lo("127.0.0.1:18080")},
		{"udp", lo("127.0.0.1:5432"), lo("127.0.0.53:53")},
		{"udp", lo("127.0.0.1:65535"), lo("[::1]:1")},
	}
	if err := ValidateHostLoopbackMappings(good); err != nil {
		t.Fatal(err)
	}
	for name, m := range map[string]HostLoopbackMapping{
		"protocol":          {"sctp", lo("127.0.0.1:1"), lo("127.0.0.1:1")},
		"session not lo":    {"tcp", lo("10.0.0.1:1"), lo("127.0.0.1:1")},
		"session 127.0.0.2": {"tcp", lo("127.0.0.2:1"), lo("127.0.0.1:1")},
		"session any":       {"tcp", lo("0.0.0.0:1"), lo("127.0.0.1:1")},
		"host lan":          {"tcp", lo("127.0.0.1:1"), lo("192.168.1.1:1")},
		"host any":          {"tcp", lo("127.0.0.1:1"), lo("[::]:1")},
		"host mapped":       {"tcp", lo("127.0.0.1:1"), lo("[::ffff:127.0.0.1]:1")},
		"session port 0":    {"tcp", lo("127.0.0.1:0"), lo("127.0.0.1:1")},
		"host port 0":       {"tcp", lo("127.0.0.1:1"), lo("127.0.0.1:0")},
	} {
		if err := ValidateHostLoopbackMappings([]HostLoopbackMapping{m}); err == nil {
			t.Errorf("%s: %v accepted", name, m)
		}
	}
	dup := []HostLoopbackMapping{{"tcp", lo("127.0.0.1:1"), lo("127.0.0.1:1")}, {"tcp", lo("127.0.0.1:1"), lo("127.0.0.1:2")}}
	if err := ValidateHostLoopbackMappings(dup); err == nil {
		t.Error("duplicate session endpoint accepted")
	}
	// The same port on the other protocol or family is a separate mapping.
	if err := ValidateHostLoopbackMappings([]HostLoopbackMapping{dup[0], {"udp", lo("127.0.0.1:1"), lo("127.0.0.1:1")}, {"tcp", lo("[::1]:1"), lo("127.0.0.1:1")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := (DirectHostLoopbackDialer{}).DialTCP(context.Background(), HostLoopbackFlow{Mapping: HostLoopbackMapping{"tcp", lo("127.0.0.1:1"), lo("192.168.1.1:80")}}); !errors.Is(err, errNotLoopback) {
		t.Fatalf("the direct dialer must refuse non-loopback targets: %v", err)
	}
	if _, err := (DirectHostLoopbackDialer{}).ListenUDP(context.Background(), HostLoopbackFlow{Mapping: HostLoopbackMapping{"udp", lo("127.0.0.1:1"), lo("8.8.8.8:53")}}); !errors.Is(err, errNotLoopback) {
		t.Fatalf("the direct dialer must refuse non-loopback targets: %v", err)
	}
}

// TestFailureReasonHidesErrorText checks that logged reasons are fixed
// classifications: error text, which may carry credentials from other parts
// of the stack, never reaches the log.
func TestFailureReasonHidesErrorText(t *testing.T) {
	secret := errors.New("dial user:hunter2@proxy failed")
	for err, want := range map[error]string{
		nil:    "none",
		secret: "other",
		fmt.Errorf("x: %w: %w", secret, syscall.ECONNREFUSED): "connection refused",
		fmt.Errorf("%w", context.DeadlineExceeded):            "timeout",
		os.ErrDeadlineExceeded:                                "timeout",
		net.ErrClosed:                                         "closed",
		fmt.Errorf("%w (256 flows)", errFlowLimit):            "UDP flow limit reached",
		errConnLimit:                                          "connection limit reached",
		errNotLoopback:                                        "target is not a loopback address",
	} {
		if got := failureReason(err); got != want || strings.Contains(got, "hunter2") {
			t.Errorf("failureReason(%v) = %q, want %q", err, got, want)
		}
	}
}
