//go:build linux && !android

package sshserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/processnet"
)

const hostLoopbackHelperEnv = "YUH_SSH_HOST_LOOPBACK_PROBES"

// hostLoopbackServers are host-side test services in Yuhaiin's own network
// namespace, each answering with its own name so a test can tell which one
// a session reached.
type hostLoopbackServers struct {
	http4, http6 netip.AddrPort
	udp4, udp6   netip.AddrPort
}

func startHostLoopbackServers(t *testing.T, ipv6 bool) hostLoopbackServers {
	t.Helper()
	var s hostLoopbackServers
	serve := func(network, address, name string) netip.AddrPort {
		l, err := net.Listen(network, address)
		if err != nil {
			t.Fatal(err)
		}
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprintf(w, "host-%s peer=%s", name, r.RemoteAddr)
		})}
		go func() { _ = server.Serve(l) }()
		t.Cleanup(func() { _ = server.Close() })
		return l.Addr().(*net.TCPAddr).AddrPort()
	}
	echo := func(network, address, name string) netip.AddrPort {
		pc, err := net.ListenPacket(network, address)
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
				_, _ = pc.WriteTo(append([]byte("host-"+name+":"), buf[:n]...), from)
			}
		}()
		return pc.LocalAddr().(*net.UDPAddr).AddrPort()
	}
	s.http4 = serve("tcp4", "127.0.0.1:0", "v4")
	s.udp4 = echo("udp4", "127.0.0.1:0", "v4")
	if ipv6 {
		s.http6 = serve("tcp6", "[::1]:0", "v6")
		s.udp6 = echo("udp6", "[::1]:0", "v6")
	}
	return s
}

func requireHostIPv6Loopback(t *testing.T) {
	t.Helper()
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("the host has no IPv6 loopback: %v", err)
	}
	_ = l.Close()
}

// recordingDialer dials directly and remembers each flow, to check process
// attribution and that only mapped endpoints are dialed.
type recordingDialer struct {
	processnet.DirectHostLoopbackDialer
	mu    sync.Mutex
	flows []processnet.HostLoopbackFlow
}

func (d *recordingDialer) record(flow processnet.HostLoopbackFlow) {
	d.mu.Lock()
	d.flows = append(d.flows, flow)
	d.mu.Unlock()
}

func (d *recordingDialer) DialTCP(ctx context.Context, flow processnet.HostLoopbackFlow) (net.Conn, error) {
	d.record(flow)
	return d.DirectHostLoopbackDialer.DialTCP(ctx, flow)
}

func (d *recordingDialer) ListenUDP(ctx context.Context, flow processnet.HostLoopbackFlow) (net.PacketConn, error) {
	d.record(flow)
	return d.DirectHostLoopbackDialer.ListenUDP(ctx, flow)
}

func (d *recordingDialer) snapshot() []processnet.HostLoopbackFlow {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]processnet.HostLoopbackFlow(nil), d.flows...)
}

func mapping(network, session string, host netip.AddrPort) processnet.HostLoopbackMapping {
	return processnet.HostLoopbackMapping{Network: network, Session: netip.MustParseAddrPort(session), Host: host}
}

// TestSSHServerHostLoopbackHelper runs inside an SSH session. Each probe is
// "kind|target|expect", separated by newlines:
//
//	http|URL|substring    GET URL and require the body to contain substring
//	udp|addr|prefix       send 3 datagrams, each echo must start with prefix
//	udpmulti|addr|prefix  4 concurrent UDP sockets doing the same
//	refused|addr|         a TCP connection must be refused
//	local|addr|           a TCP service started here, on the session loopback
//
// It prints "PASS <probe>" or "FAIL <probe>: reason" per probe.
func TestSSHServerHostLoopbackHelper(t *testing.T) {
	spec := os.Getenv(hostLoopbackHelperEnv)
	if spec == "" {
		t.Skip("SSH host loopback helper")
	}
	for _, line := range strings.Split(spec, "\n") {
		fields := strings.SplitN(line, "|", 3)
		if len(fields) != 3 {
			continue
		}
		if err := runHostLoopbackProbe(fields[0], fields[1], fields[2]); err != nil {
			fmt.Printf("FAIL %s: %v\n", line, err)
		} else {
			fmt.Printf("PASS %s\n", line)
		}
	}
}

func runHostLoopbackProbe(kind, target, expect string) error {
	switch kind {
	case "http":
		client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
		resp, err := client.Get(target)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		if !strings.Contains(string(body), expect) {
			return fmt.Errorf("body %q lacks %q", body, expect)
		}
		return nil
	case "udp":
		return udpEchoProbe(target, expect, "s")
	case "udpmulti":
		var wg sync.WaitGroup
		errs := make([]error, 4)
		for i := range errs {
			wg.Go(func() { errs[i] = udpEchoProbe(target, expect, fmt.Sprintf("flow%d", i)) })
		}
		wg.Wait()
		return errors.Join(errs...)
	case "refused":
		c, err := net.DialTimeout("tcp", target, 3*time.Second)
		if err == nil {
			_ = c.Close()
			return errors.New("connected")
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return err
		}
		return nil
	case "local":
		l, err := net.Listen("tcp", target)
		if err != nil {
			return err
		}
		defer l.Close()
		go func() {
			if c, err := l.Accept(); err == nil {
				_, _ = c.Write([]byte("session-local"))
				_ = c.Close()
			}
		}()
		c, err := net.DialTimeout("tcp", target, 3*time.Second)
		if err != nil {
			return err
		}
		defer c.Close()
		got, err := io.ReadAll(c)
		if err != nil || string(got) != "session-local" {
			return fmt.Errorf("got %q, %v", got, err)
		}
		return nil
	}
	return fmt.Errorf("unknown probe %q", kind)
}

func udpEchoProbe(target, prefix, tag string) error {
	c, err := net.Dial("udp", target)
	if err != nil {
		return err
	}
	defer c.Close()
	for i := range 3 {
		payload := fmt.Sprintf("%s-%d", tag, i)
		if _, err := c.Write([]byte(payload)); err != nil {
			return err
		}
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 2048)
		n, err := c.Read(buf)
		if err != nil {
			return err
		}
		if want := prefix + payload; string(buf[:n]) != want {
			return fmt.Errorf("echo %q, want %q (datagram boundaries must be kept)", buf[:n], want)
		}
	}
	return nil
}

func hostLoopbackProbeCommand(binary string, probes []string) string {
	return fmt.Sprintf("%s=%s %s -test.run='^TestSSHServerHostLoopbackHelper$' -test.v", hostLoopbackHelperEnv,
		sshShellQuote(strings.Join(probes, "\n")), sshShellQuote(binary))
}

func checkProbeOutput(t *testing.T, out string, probes []string) {
	t.Helper()
	for _, probe := range probes {
		if !strings.Contains(out, "PASS "+probe+"\n") {
			t.Errorf("probe %q did not pass", probe)
		}
	}
	if strings.Contains(out, "FAIL ") {
		t.Errorf("session probes:\n%s", out)
	}
}

func nftRuleset() (string, bool) {
	out, err := exec.Command("nft", "list", "ruleset").Output()
	return string(out), err == nil
}

// TestSSHServerHostLoopbackForwarding runs the feature end to end: an SSH
// session reaches host loopback services through 127.0.0.1 and ::1 on mapped
// ports, over TCP and UDP, across address families and with different host
// ports, while unmapped ports and session-local services stay in the session.
func TestSSHServerHostLoopbackForwarding(t *testing.T) {
	requireSSHSessionIntegration(t)
	requireHostIPv6Loopback(t)
	host := startHostLoopbackServers(t, true)
	before := hostNetworkState(t)
	nftBefore, nftOK := nftRuleset()

	dialer := &recordingDialer{DirectHostLoopbackDialer: processnet.DirectHostLoopbackDialer{Timeout: 5 * time.Second}}
	config, signer := newSSHServerTestIdentity(t)
	config.IPv6 = true
	config.HostLoopback = []processnet.HostLoopbackMapping{
		mapping("tcp", "127.0.0.1:8080", host.http4), // different host port
		mapping("tcp", "[::1]:8080", host.http6),
		mapping("tcp", "[::1]:8081", host.http4),     // IPv6 session -> IPv4 host
		mapping("tcp", "127.0.0.1:8082", host.http6), // IPv4 session -> IPv6 host
		mapping("udp", "127.0.0.1:5353", host.udp4),
		mapping("udp", "[::1]:5353", host.udp6),
		mapping("udp", "[::1]:5354", host.udp4),
	}
	config.HostLoopbackDialer = dialer
	handler := newSSHServerTestHandler()
	server := startSSHServerTestServer(t, config, handler)
	client := dialSSHServer(t, server, config.Username, signer)
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	probes := []string{
		"http|http://127.0.0.1:8080/|host-v4",
		"http|http://[::1]:8080/|host-v6",
		"http|http://localhost:8080/|host-", // either family: both are mapped
		"http|http://[::1]:8081/|host-v4",
		"http|http://127.0.0.1:8082/|host-v6",
		"udp|127.0.0.1:5353|host-v4:",
		"udp|[::1]:5353|host-v6:",
		"udp|[::1]:5354|host-v4:",
		"udpmulti|127.0.0.1:5353|host-v4:",
		"udpmulti|[::1]:5353|host-v6:",
		// Not mapped: other ports, and the other family of mapped ports.
		"refused|127.0.0.1:8083|",
		"refused|127.0.0.1:8081|",
		"refused|[::1]:8082|",
		// Unmapped ports are the session's own loopback.
		"local|127.0.0.1:8090|",
		"local|[::1]:8090|",
	}
	out := string(runSSHCommand(t, client, hostLoopbackProbeCommand(binary, probes)))
	t.Logf("session probes:\n%s", out)
	checkProbeOutput(t, out, probes)

	// Every dial targeted a mapped host endpoint, attributed to the session
	// process that connected from the session loopback.
	allowed := map[netip.AddrPort]bool{host.http4: true, host.http6: true, host.udp4: true, host.udp6: true}
	flows := dialer.snapshot()
	if len(flows) == 0 {
		t.Fatal("no forwarded flows were dialed")
	}
	for _, flow := range flows {
		if !allowed[flow.Mapping.Host] || !flow.Source.Addr().IsLoopback() || flow.InboundID != server.config.InboundID {
			t.Errorf("unexpected flow %+v", flow)
		}
		if !strings.HasSuffix(flow.Process, ".test") || flow.PID == 0 {
			t.Errorf("flow %s lost its process: %+v", flow.Mapping, flow)
		}
	}
	// Forwarded flows never enter the session TUN or the inbound handler.
	for {
		select {
		case dst := <-handler.streams:
			if dst.Addr().IsLoopback() || dst.Port() == 8080 || dst.Port() == 8081 || dst.Port() == 8082 {
				t.Errorf("the inbound handler saw a forwarded destination %s", dst)
			}
			continue
		default:
		}
		break
	}
	_ = client.Close()
	if after := hostNetworkState(t); after != before {
		t.Fatalf("host network changed:\nbefore %s\nafter %s", before, after)
	}
	if nftAfter, ok := nftRuleset(); nftOK && ok && nftAfter != nftBefore {
		t.Fatal("the host nftables ruleset changed")
	}
}

// TestSSHServerHostLoopbackSingleFamily maps only IPv4. localhost still works
// for clients that fall back from ::1 to 127.0.0.1, and ::1 is refused by the
// session loopback instead of being forwarded somewhere else.
func TestSSHServerHostLoopbackSingleFamily(t *testing.T) {
	requireSSHSessionIntegration(t)
	host := startHostLoopbackServers(t, false)
	config, signer := newSSHServerTestIdentity(t)
	config.HostLoopback = []processnet.HostLoopbackMapping{mapping("tcp", "127.0.0.1:8080", host.http4)}
	server := startSSHServerTestServer(t, config, newSSHServerTestHandler())
	client := dialSSHServer(t, server, config.Username, signer)
	binary, _ := os.Executable()
	probes := []string{
		"http|http://127.0.0.1:8080/|host-v4",
		"http|http://localhost:8080/|host-v4",
		"refused|[::1]:8080|",
	}
	checkProbeOutput(t, string(runSSHCommand(t, client, hostLoopbackProbeCommand(binary, probes))), probes)
}

// TestSSHServerHostLoopbackHostServiceDown checks that a mapping whose host
// service is not listening fails the session's connection promptly, without
// retrying another family.
func TestSSHServerHostLoopbackHostServiceDown(t *testing.T) {
	requireSSHSessionIntegration(t)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	down := l.Addr().(*net.TCPAddr).AddrPort()
	_ = l.Close()
	dialer := &recordingDialer{DirectHostLoopbackDialer: processnet.DirectHostLoopbackDialer{Timeout: 5 * time.Second}}
	config, signer := newSSHServerTestIdentity(t)
	config.HostLoopback = []processnet.HostLoopbackMapping{mapping("tcp", "127.0.0.1:8080", down)}
	config.HostLoopbackDialer = dialer
	server := startSSHServerTestServer(t, config, newSSHServerTestHandler())
	client := dialSSHServer(t, server, config.Username, signer)
	binary, _ := os.Executable()
	started := time.Now()
	out := string(runSSHCommand(t, client, hostLoopbackProbeCommand(binary, []string{"http|http://127.0.0.1:8080/|x"})))
	if !strings.Contains(out, "FAIL http|http://127.0.0.1:8080/|x") || time.Since(started) > 10*time.Second {
		t.Fatalf("a stopped host service must fail promptly: %s", out)
	}
	for _, flow := range dialer.snapshot() {
		if flow.Mapping.Host != down {
			t.Fatalf("dialed an unexpected target %s", flow.Mapping.Host)
		}
	}
}

// TestSSHServerHostLoopbackSessionsAreSeparate opens two SSH transports. Each
// gets its own session and sockets; closing one leaves the other working, and
// closing both releases every descriptor.
func TestSSHServerHostLoopbackSessionsAreSeparate(t *testing.T) {
	requireSSHSessionIntegration(t)
	host := startHostLoopbackServers(t, false)
	config, signer := newSSHServerTestIdentity(t)
	config.HostLoopback = []processnet.HostLoopbackMapping{mapping("tcp", "127.0.0.1:8080", host.http4), mapping("udp", "127.0.0.1:5353", host.udp4)}
	server := startSSHServerTestServer(t, config, newSSHServerTestHandler())
	binary, _ := os.Executable()
	probes := []string{"http|http://127.0.0.1:8080/|host-v4", "udp|127.0.0.1:5353|host-v4:"}
	// Warm up so descriptors opened once per process are not counted.
	warm := dialSSHServer(t, server, config.Username, signer)
	checkProbeOutput(t, string(runSSHCommand(t, warm, hostLoopbackProbeCommand(binary, probes))), probes)
	_ = warm.Close()
	time.Sleep(500 * time.Millisecond)
	fds := openFDCount(t)

	a := dialSSHServer(t, server, config.Username, signer)
	b := dialSSHServer(t, server, config.Username, signer)
	nsA := string(runSSHCommand(t, a, "readlink /proc/self/ns/net"))
	nsB := string(runSSHCommand(t, b, "readlink /proc/self/ns/net"))
	if nsA == nsB {
		t.Fatalf("two SSH transports share network namespace %s", nsA)
	}
	checkProbeOutput(t, string(runSSHCommand(t, a, hostLoopbackProbeCommand(binary, probes))), probes)
	_ = a.Close()
	// Session B is unaffected by A's teardown.
	checkProbeOutput(t, string(runSSHCommand(t, b, hostLoopbackProbeCommand(binary, probes))), probes)
	_ = b.Close()
	deadline := time.Now().Add(5 * time.Second)
	for openFDCount(t) > fds && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if after := openFDCount(t); after > fds {
		t.Fatalf("%d descriptors leaked after both sessions closed", after-fds)
	}
}

func openFDCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func TestValidateHostLoopbackConfig(t *testing.T) {
	c := testConfig(t)
	c.HostLoopback = []processnet.HostLoopbackMapping{
		mapping("tcp", "127.0.0.1:5432", netip.MustParseAddrPort("127.0.0.1:5432")),
		mapping("tcp", "127.0.0.1:5432", netip.MustParseAddrPort("127.0.0.1:5433")),
	}
	if _, _, err := c.validate(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate session endpoints must be refused: %v", err)
	}
	c = testConfig(t)
	c.HostLoopback = []processnet.HostLoopbackMapping{mapping("tcp", "127.0.0.1:5432", netip.MustParseAddrPort("192.168.1.10:5432"))}
	if _, _, err := c.validate(); err == nil {
		t.Fatal("a non-loopback host target must be refused")
	}
}
