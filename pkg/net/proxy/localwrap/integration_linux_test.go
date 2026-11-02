//go:build linux && !android

package localwrap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type integrationHandler struct {
	tcp, udp, dnsTCP, dnsUDP atomic.Int32
	failures                 chan error
}

func (h *integrationHandler) checkScope(network string, scope netapi.ProcessDumper, src, dst net.Addr) {
	if scope == nil {
		h.failures <- fmt.Errorf("missing %s process scope", network)
		return
	}
	a, err := netapi.ParseSysAddr(src)
	if err != nil {
		h.failures <- err
		return
	}
	b, err := netapi.ParseSysAddr(dst)
	if err != nil {
		h.failures <- err
		return
	}
	process, err := scope.ProcessName(network, a, b)
	if err != nil || process.Pid == 0 {
		h.failures <- fmt.Errorf("%s process lookup: %+v %v", network, process, err)
	}
}

func (h *integrationHandler) HandleStream(m *netapi.StreamMeta) {
	defer m.Src.Close()
	if !m.DnsRequest {
		h.tcp.Add(1)
		h.checkScope("tcp", m.ProcessScope, m.Source, m.Destination)
		_, _ = io.Copy(m.Src, m.Src)
		return
	}
	h.dnsTCP.Add(1)
	var length [2]byte
	if _, err := io.ReadFull(m.Src, length[:]); err != nil {
		return
	}
	query := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(m.Src, query); err != nil {
		return
	}
	response, err := integrationDNS(query)
	if err != nil {
		h.failures <- err
		return
	}
	binary.BigEndian.PutUint16(length[:], uint16(len(response)))
	_, _ = m.Src.Write(append(length[:], response...))
}
func (h *integrationHandler) HandlePacket(p *netapi.Packet) {
	defer p.DecRef()
	payload := p.GetPayload()
	if p.IsDNSRequest() {
		h.dnsUDP.Add(1)
		var err error
		payload, err = integrationDNS(payload)
		if err != nil {
			h.failures <- err
			return
		}
	} else {
		h.udp.Add(1)
		h.checkScope("udp", p.ProcessScope, p.Src(), p.Dst())
	}
	if _, err := p.WriteBack(payload, p.Dst()); err != nil {
		h.failures <- err
	}
}
func (*integrationHandler) HandlePing(*netapi.PingMeta) {}

func integrationDNS(wire []byte) ([]byte, error) {
	req := &dns.Msg{Data: wire}
	if err := req.Unpack(); err != nil {
		return nil, err
	}
	response := new(dns.Msg)
	dnsutil.SetReply(response, req)
	response.RecursionAvailable = true
	for _, q := range req.Question {
		if q.Header().Name != "wrap.test." {
			continue
		}
		hdr := dns.Header{Name: q.Header().Name, Class: dns.ClassINET, TTL: 30}
		switch dns.RRToType(q) {
		case dns.TypeA:
			response.Answer = append(response.Answer, &dns.A{Hdr: hdr, Addr: netip.MustParseAddr("198.51.100.42")})
		case dns.TypeAAAA:
			response.Answer = append(response.Answer, &dns.AAAA{Hdr: hdr, Addr: netip.MustParseAddr("2001:db8::42")})
		}
	}
	if err := response.Pack(); err != nil {
		return nil, err
	}
	return response.Data, nil
}

func integrationServer(t testing.TB) (*Server, string, *integrationHandler) {
	t.Helper()
	if os.Getenv("YUH_WRAP_INTEGRATION") != "1" && os.Getenv("YUH_WRAP_NAMESPACE_TEST") != "1" {
		t.Skip("enable YUH_WRAP_INTEGRATION with cgroup v2 or YUH_WRAP_NAMESPACE_TEST in a disposable user namespace")
	}
	dir, err := os.MkdirTemp("", "yuhaiin-wrap-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	binaryPath := filepath.Join(dir, "wrap-probe")
	target, err := os.OpenFile(binaryPath, os.O_CREATE|os.O_WRONLY, 0755)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(target, source)
	closeErr := target.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("copy helper: %v %v", err, closeErr)
	}
	handler := &integrationHandler{failures: make(chan error, 64)}
	config := Config{Socket: filepath.Join(dir, "wrap.sock"), UID: 65534, GID: 65534, IPv6: true, MaxSessions: 8}
	var server *Server
	if os.Getenv("YUH_WRAP_INTEGRATION") == "1" {
		root := os.Getenv("YUH_WRAP_CGROUP_ROOT")
		if root == "" {
			t.Fatal("YUH_WRAP_CGROUP_ROOT must specify a dedicated writable cgroup v2 root")
		}
		config.CgroupRoot = root
		server, err = NewServer(config, handler)
	} else {
		server, err = listen(config, handler, nil, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})
	return server, binaryPath, handler
}

func integrationClient(t testing.TB, server *Server, binaryPath string, args ...string) *exec.Cmd {
	t.Helper()
	command := exec.Command(binaryPath, append([]string{"-test.run=^TestWrapClientHelper$", "--"}, args...)...)
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/", "YUH_WRAP_CLIENT_HELPER=1", "YUH_WRAP_SOCKET=" + server.config.Socket}
	command.Dir = filepath.Dir(binaryPath)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	return command
}

func TestWrapClientHelper(t *testing.T) {
	if os.Getenv("YUH_WRAP_CLIENT_HELPER") != "1" {
		t.Skip("local wrap subprocess helper")
	}
	index := slices.Index(os.Args, "--")
	if index < 0 {
		os.Exit(125)
	}
	code, err := Run(context.Background(), Options{Socket: os.Getenv("YUH_WRAP_SOCKET"), Argv: os.Args[index+1:]})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(code)
}

func TestWrapNetworkProbe(t *testing.T) {
	if os.Getenv("YUH_WRAP_CLIENT_HELPER") != "1" {
		t.Skip("isolated network probe")
	}
	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		host := "198.51.100.42"
		if strings.HasSuffix(network, "6") {
			host = "2001:db8::42"
		}
		conn, err := net.DialTimeout(network, net.JoinHostPort(host, "18080"), 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		payload := []byte("wrap-network-payload")
		if _, err := conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("%s echo: %q %v", network, got, err)
		}
		_ = conn.Close()
	}
	resolver := &net.Resolver{PreferGo: true}
	addresses, err := resolver.LookupHost(t.Context(), "wrap.test")
	if err != nil || !slices.Contains(addresses, "198.51.100.42") || !slices.Contains(addresses, "2001:db8::42") {
		t.Fatalf("DNS UDP: %v %v", addresses, err)
	}
	response, err := dns.Exchange(t.Context(), dns.NewMsg("wrap.test.", dns.TypeA), "tcp", "172.31.254.1:53")
	if err != nil || len(response.Answer) != 1 {
		t.Fatalf("DNS TCP: %v %v", response, err)
	}
}

func TestLocalWrapNetworkIntegration(t *testing.T) {
	server, binaryPath, handler := integrationServer(t)
	command := integrationClient(t, server, binaryPath, binaryPath, "-test.run=^TestWrapNetworkProbe$")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("isolated network: %v\n%s", err, output)
	}
	if handler.tcp.Load() != 2 || handler.udp.Load() != 2 || handler.dnsTCP.Load() == 0 || handler.dnsUDP.Load() == 0 {
		t.Fatalf("missing routed traffic: TCP=%d UDP=%d DNS TCP=%d UDP=%d", handler.tcp.Load(), handler.udp.Load(), handler.dnsTCP.Load(), handler.dnsUDP.Load())
	}
	select {
	case err := <-handler.failures:
		t.Fatal(err)
	default:
	}
	hostNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	command = integrationClient(t, server, binaryPath, "/bin/sh", "-c", `readlink /proc/self/ns/net; sh -c 'readlink /proc/self/ns/net'; id -u; getent ahostsv4 wrap.test`)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("libc resolver and descendants: %v\n%s", err, output)
	}
	lines := strings.Split(string(output), "\n")
	if len(lines) < 5 || lines[0] == hostNS || lines[0] != lines[1] || lines[2] != "65534" || !strings.Contains(string(output), "198.51.100.42") {
		t.Fatalf("namespace, identity or libc DNS mismatch: %s", output)
	}
}

func TestLocalWrapSignalIntegration(t *testing.T) {
	server, binaryPath, _ := integrationServer(t)
	command := integrationClient(t, server, binaryPath, "/bin/sh", "-c", "echo READY; exec /bin/sleep 300")
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill() }()
	if line, err := bufio.NewReader(output).ReadString('\n'); err != nil || line != "READY\n" {
		t.Fatalf("command readiness: %q %v", line, err)
	}
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); exitCode(err) != 143 {
		t.Fatalf("forwarded SIGTERM exit: %v", err)
	}
}

func TestLocalWrapConcurrentNamespacesIntegration(t *testing.T) {
	server, binaryPath, _ := integrationServer(t)
	type result struct {
		output []byte
		err    error
	}
	results := make(chan result, 2)
	for range 2 {
		command := integrationClient(t, server, binaryPath, "/bin/sh", "-c", "readlink /proc/self/ns/net; sleep 0.2")
		go func() { output, err := command.CombinedOutput(); results <- result{output, err} }()
	}
	var namespaces []string
	for range 2 {
		res := <-results
		if res.err != nil {
			t.Fatalf("concurrent launch: %v\n%s", res.err, res.output)
		}
		namespaces = append(namespaces, strings.TrimSpace(string(res.output)))
	}
	if namespaces[0] == namespaces[1] {
		t.Fatalf("independent invocations shared a namespace: %s", namespaces[0])
	}
}

func TestLocalWrapContainmentIntegration(t *testing.T) {
	if os.Getenv("YUH_WRAP_INTEGRATION") != "1" {
		t.Skip("requires the production cgroup v2 supervisor")
	}
	server, binaryPath, _ := integrationServer(t)
	command := integrationClient(t, server, binaryPath, "/bin/sh", "-c", "setsid /bin/sleep 300 </dev/null >/dev/null 2>&1 & echo $!")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("detached descendant: %v\n%s", err, output)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil {
		t.Fatal(err)
	}
	// An orphan may briefly remain as a zombie until PID 1 reaps it.
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err == nil {
		_, state, ok := strings.Cut(string(stat), ") ")
		if !ok || !strings.HasPrefix(state, "Z ") {
			t.Fatalf("detached descendant is still alive: %s", stat)
		}
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(server.config.CgroupRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "session-") {
			t.Fatalf("session cgroup leaked: %s", entry.Name())
		}
	}
}

func TestLocalWrapShutdownIntegration(t *testing.T) {
	server, binaryPath, _ := integrationServer(t)
	command := integrationClient(t, server, binaryPath, "/bin/sh", "-c", "echo READY; exec /bin/sleep 300")
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill() }()
	if line, err := bufio.NewReader(output).ReadString('\n'); err != nil || line != "READY\n" {
		t.Fatalf("command readiness: %q %v", line, err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); exitCode(err) != 125 {
		t.Fatalf("shutdown must report a failed local session: %v", err)
	}
}

func BenchmarkIsolatedCommand(b *testing.B) {
	server, binaryPath, _ := integrationServer(b)
	b.ReportAllocs()
	for b.Loop() {
		command := integrationClient(b, server, binaryPath, "/bin/true")
		if output, err := command.CombinedOutput(); err != nil {
			b.Fatalf("isolated command: %v\n%s", err, output)
		}
	}
}
