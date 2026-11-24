//go:build linux && !android

package sshserver

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/yuhaiin/sessionnet"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// sshProcessTree leaves background, nested, setsid-detached and
// double-forked processes behind, then prints the session's PID namespace.
const sshProcessTree = `sleep 300 &
(sleep 300 &) &
sh -c 'sh -c "sleep 300 & sleep 300" &' &
setsid sleep 300 < /dev/null > /dev/null 2>&1 &
nohup sh -c 'sleep 300' > /dev/null 2>&1 &
sleep 0.3
echo "PIDNS $(readlink /proc/self/ns/pid)"
`

func pidNamespaceMembers(pidns string) []int {
	entries, _ := os.ReadDir("/proc")
	var pids []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		if link, err := os.Readlink(filepath.Join("/proc", entry.Name(), "ns/pid")); err == nil && link == pidns {
			pids = append(pids, pid)
		}
	}
	return pids
}

func waitPIDNamespaceEmpty(t testing.TB, pidns string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		left := pidNamespaceMembers(pidns)
		if len(left) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("processes of SSH session %s survived: %v", pidns, left)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// startDetachedTree runs sshProcessTree in a channel that stays open, and
// returns the session's PID namespace once the tree is running.
func startDetachedTree(t *testing.T, client *gossh.Client, tail string) (*gossh.Session, string) {
	t.Helper()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Start(sshProcessTree + tail); err != nil {
		t.Fatal(err)
	}
	found := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if ns, ok := strings.CutPrefix(scanner.Text(), "PIDNS "); ok {
				found <- ns
			}
		}
		_, _ = io.Copy(io.Discard, stdout)
	}()
	select {
	case pidns := <-found:
		if n := len(pidNamespaceMembers(pidns)); n < 6 {
			t.Fatalf("expected the detached process tree to be running, found %d processes", n)
		}
		return session, pidns
	case <-time.After(10 * time.Second):
		t.Fatal("process tree did not start")
		return nil, ""
	}
}

func TestSSHServerDisconnectKillsAllDescendants(t *testing.T) {
	requireSSHSessionIntegration(t)
	for _, scenario := range []struct {
		name       string
		tail       string
		disconnect func(*gossh.Client, *gossh.Session, net.Conn)
	}{
		// The command finished but left detached children; the client then
		// closes the transport normally.
		{"normal close after exec", "", func(c *gossh.Client, s *gossh.Session, _ net.Conn) { _ = s.Wait(); _ = c.Close() }},
		// The client process dies: the TCP connection vanishes mid-exec.
		{"abrupt TCP close during exec", "sleep 300", func(_ *gossh.Client, _ *gossh.Session, raw net.Conn) { _ = raw.Close() }},
		// The interactive shell is still running when the transport closes.
		{"close during shell", "exec sh -c 'read -r x'", func(c *gossh.Client, _ *gossh.Session, _ net.Conn) { _ = c.Close() }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			config, signer := newSSHServerTestIdentity(t)
			server := startSSHServerTestServer(t, config, newSSHServerTestHandler())
			raw, err := net.DialTimeout("tcp", server.listener.Addr().String(), 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			conn, chans, reqs, err := gossh.NewClientConn(raw, "", sshClientConfig(config.Username, signer))
			if err != nil {
				t.Fatal(err)
			}
			client := gossh.NewClient(conn, chans, reqs)
			defer client.Close()
			session, pidns := startDetachedTree(t, client, scenario.tail)
			scenario.disconnect(client, session, raw)
			waitPIDNamespaceEmpty(t, pidns)
		})
	}
}

// TestSSHServerSupervisorCrashRecovers kills the session supervisor from
// outside. Its processes die with the PID namespace, the running command
// fails, and the next command gets a fresh session instead of a dead one.
func TestSSHServerSupervisorCrashRecovers(t *testing.T) {
	requireSSHSessionIntegration(t)
	config, signer := newSSHServerTestIdentity(t)
	server := startSSHServerTestServer(t, config, newSSHServerTestHandler())
	client := dialSSHServer(t, server, config.Username, signer)
	session, pidns := startDetachedTree(t, client, "sleep 300")
	supervisor := 0
	for _, pid := range pidNamespaceMembers(pidns) {
		if cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); bytes.HasPrefix(cmdline, []byte("sessionnet-supervisor")) {
			supervisor = pid
		}
	}
	if supervisor == 0 {
		t.Fatal("session supervisor not found")
	}
	// Keep the old PID namespace's inode allocated so a recycled inode
	// number cannot look like the same namespace.
	pin, err := os.Open(fmt.Sprintf("/proc/%d/ns/pid", supervisor))
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	if err := syscall.Kill(supervisor, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	var exit *gossh.ExitError
	if err := session.Wait(); err == nil || !errors.As(err, &exit) || exit.ExitStatus() != 255 {
		t.Fatalf("command of a killed supervisor: %v", err)
	}
	waitPIDNamespaceEmpty(t, pidns)
	if out := runSSHCommand(t, client, "readlink /proc/self/ns/pid"); strings.TrimSpace(string(out)) == pidns {
		t.Fatal("a dead session was reused")
	}
}

// TestSSHServerYuhaiinCrashKillsSessions runs the SSH server in a child
// process, kills it with SIGKILL, and checks that its sessions die.
func TestSSHServerYuhaiinCrashKillsSessions(t *testing.T) {
	requireSSHSessionIntegration(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestSSHServerCrashHelper$")
	cmd.Env = append(os.Environ(), "YUH_SSH_CRASH_HELPER=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	scanner := bufio.NewScanner(stdout)
	pidns := ""
	for scanner.Scan() {
		if ns, ok := strings.CutPrefix(scanner.Text(), "CRASH-PIDNS "); ok {
			pidns = ns
			break
		}
	}
	if pidns == "" {
		t.Fatal("crash helper did not start a session")
	}
	if n := len(pidNamespaceMembers(pidns)); n < 6 {
		t.Fatalf("expected a live session tree, found %d", n)
	}
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	waitPIDNamespaceEmpty(t, pidns)
}

func TestSSHServerCrashHelper(t *testing.T) {
	if os.Getenv("YUH_SSH_CRASH_HELPER") != "1" {
		t.Skip("crash helper")
	}
	config, signer := newSSHServerTestIdentity(t)
	server := startSSHServerTestServer(t, config, newSSHServerTestHandler())
	client := dialSSHServer(t, server, config.Username, signer)
	_, pidns := startDetachedTree(t, client, "sleep 300")
	fmt.Printf("CRASH-PIDNS %s\n", pidns)
	time.Sleep(time.Minute)
}

func TestSSHServerForwardsSignals(t *testing.T) {
	requireSSHSessionIntegration(t)
	config, signer := newSSHServerTestIdentity(t)
	server := startSSHServerTestServer(t, config, newSSHServerTestHandler())
	client := dialSSHServer(t, server, config.Username, signer)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Start("trap 'echo got-term; exit 0' TERM; echo ready; while :; do sleep 0.05; done"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(stdout)
	if line, err := reader.ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("%q %v", line, err)
	}
	if err := session.Signal(gossh.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if line, err := reader.ReadString('\n'); err != nil || line != "got-term\n" {
		t.Fatalf("signal was not forwarded: %q %v", line, err)
	}
	if err := session.Wait(); err != nil {
		t.Fatal(err)
	}
}

// TestSSHServerIsolationAcrossTransports checks loopback ports, resolver and
// host network invariants for two transports.
func TestSSHServerIsolationAcrossTransports(t *testing.T) {
	requireSSHSessionIntegration(t)
	before := hostNetworkState(t)
	// Compare contents: the test itself may run inside another session.
	originalResolv, _ := os.ReadFile("/etc/resolv.conf")
	config, signer := newSSHServerTestIdentity(t)
	server := startSSHServerTestServer(t, config, newSSHServerTestHandler())
	binary := sshServerTestBinary(t)
	listen := fmt.Sprintf("YUH_SSH_LISTEN=1 %s -test.run='^TestSSHServerLoopbackHelper$'", sshShellQuote(binary))
	var keepers []*gossh.Session
	for i := range 2 {
		client := dialSSHServer(t, server, config.Username, signer)
		session, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		keepers = append(keepers, session)
		stdout, err := session.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := session.Start(listen); err != nil {
			t.Fatal(err)
		}
		if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "LISTENING\n" {
			t.Fatalf("transport %d could not bind the shared loopback port: %q %v", i, line, err)
		}
		out := runSSHCommand(t, client, "cat /etc/resolv.conf")
		if !bytes.Contains(out, []byte("nameserver "+sessionnet.GatewayIPv4)) {
			t.Fatalf("transport %d resolver: %s", i, out)
		}
	}
	// A host loopback listener is unreachable from inside sessions.
	host, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	client := dialSSHServer(t, server, config.Username, signer)
	probe := fmt.Sprintf("YUH_SSH_DIAL=%s %s -test.run='^TestSSHServerLoopbackHelper$'", host.Addr(), sshShellQuote(binary))
	if out := runSSHCommand(t, client, probe); !bytes.Contains(out, []byte("ISOLATED")) {
		t.Fatalf("session reached the host loopback: %s", out)
	}
	for _, k := range keepers {
		_ = k.Close()
	}
	if after := hostNetworkState(t); after != before {
		t.Fatalf("host network changed:\n%s\n---\n%s", before, after)
	}
	if hostResolv, err := os.ReadFile("/etc/resolv.conf"); err == nil && !bytes.Equal(hostResolv, originalResolv) {
		t.Fatal("host resolver was modified")
	}
}

func TestSSHServerLoopbackHelper(t *testing.T) {
	if target := os.Getenv("YUH_SSH_DIAL"); target != "" {
		if conn, err := net.DialTimeout("tcp", target, time.Second); err == nil {
			_ = conn.Close()
			fmt.Println("REACHED")
		} else {
			fmt.Println("ISOLATED")
		}
		return
	}
	if os.Getenv("YUH_SSH_LISTEN") != "1" {
		t.Skip("loopback helper")
	}
	l, err := net.Listen("tcp", "127.0.0.1:47321")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	fmt.Println("LISTENING")
	time.Sleep(time.Minute)
}

func hostNetworkState(t testing.TB) string {
	t.Helper()
	var b strings.Builder
	// Route tables carry live reference and use counters (/proc/net/route
	// RefCnt/Use, ipv6_route refcnt/use) that change with any host traffic;
	// compare only the route definitions.
	for _, table := range []struct {
		file    string
		counter map[int]bool
	}{{"/proc/net/route", map[int]bool{4: true, 5: true}}, {"/proc/net/ipv6_route", map[int]bool{6: true, 7: true}}} {
		data, _ := os.ReadFile(table.file)
		for _, line := range strings.Split(string(data), "\n") {
			for i, field := range strings.Fields(line) {
				if !table.counter[i] {
					b.WriteString(field + " ")
				}
			}
			b.WriteString("\n")
		}
	}
	data, _ := os.ReadFile("/proc/net/dev_mcast")
	b.Write(data)
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		addrs, _ := iface.Addrs()
		fmt.Fprintf(&b, "%s %v %v\n", iface.Name, iface.Flags, addrs)
	}
	for _, args := range [][]string{{"rule"}, {"-6", "rule"}} {
		if out, err := exec.Command("ip", args...).Output(); err == nil {
			b.Write(out)
		}
	}
	return b.String()
}

// TestSSHServerRootlessRunsUnprivileged proves the rootless tests exercised
// the real feature: no root, no capability, no host namespace changes.
func TestSSHServerRootlessRunsUnprivileged(t *testing.T) {
	requireSSHSessionIntegration(t)
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 || data[0].Effective != 0 || data[1].Effective != 0 {
		if os.Getenv("YUH_REQUIRE_ROOTLESS") == "1" {
			t.Fatal("rootless verification must run as a normal user without capabilities")
		}
		t.Skip("running with privileges; this run does not prove rootless operation")
	}
	config, signer := newSSHServerTestIdentity(t)
	server := startSSHServerTestServer(t, config, newSSHServerTestHandler())
	if server.config.NamespaceMode != NamespaceModeRootless {
		t.Fatalf("mode %q", server.config.NamespaceMode)
	}
	client := dialSSHServer(t, server, config.Username, signer)
	out := string(runSSHCommand(t, client, "id -u; grep -E '^(CapEff|CapPrm|CapBnd|CapAmb|NoNewPrivs)' /proc/self/status"))
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if own := testOwnIdentity(t); lines[0] != strconv.FormatUint(uint64(own.UID), 10) {
		t.Fatalf("shell UID %q, want the Yuhaiin user %d", lines[0], own.UID)
	}
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if fields[0] == "NoNewPrivs:" && fields[1] != "1" || fields[0] != "NoNewPrivs:" && fields[1] != "0000000000000000" {
			t.Fatalf("shell privileges: %s", out)
		}
	}
	t.Logf("verified rootless SSH: euid=%d, no capabilities in Yuhaiin or the shell", os.Geteuid())
}

// TestSSHServerPreflightReportsUnmappableUID shows the inbound refuses to
// start, with an actionable message, when rootless mode cannot honor the
// configured UID.
func TestSSHServerPreflightReportsUnmappableUID(t *testing.T) {
	requireSSHSessionIntegration(t)
	if testHostRoot() {
		t.Skip("root may map any UID")
	}
	config, _ := newSSHServerTestIdentity(t)
	config.InboundID = "preflight"
	config.UID = testOwnIdentity(t).UID + 1
	server, err := NewServer(config, newSSHServerTestHandler())
	if err == nil {
		_ = server.Close()
		t.Skip("this host delegates the UID through /etc/subuid")
	}
	if !strings.Contains(err.Error(), "UID mapping failed") || !strings.Contains(err.Error(), "rootless") {
		t.Fatalf("unhelpful preflight error: %v", err)
	}
}
