//go:build linux && !android

package sshserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	gossh "golang.org/x/crypto/ssh"
)

const (
	sshIntegrationEnv = "YUH_SSH_SERVER_INTEGRATION"
	sshHelperModeEnv  = "YUH_SSH_SERVER_HELPER_MODE"
	sshDNSName        = "network-space.ssh.test."
	sshDNSIPv4        = "198.51.100.42"
	sshDNSIPv6        = "2001:db8::42"
)

type sshServerTestHandler struct {
	tcp       chan struct{}
	udp       chan struct{}
	dnsTCP    chan struct{}
	dnsUDP    chan struct{}
	dnsErrors chan error
}

func newSSHServerTestHandler() *sshServerTestHandler {
	return &sshServerTestHandler{
		tcp:       make(chan struct{}, 64),
		udp:       make(chan struct{}, 64),
		dnsTCP:    make(chan struct{}, 64),
		dnsUDP:    make(chan struct{}, 64),
		dnsErrors: make(chan error, 64),
	}
}

func (h *sshServerTestHandler) HandleStream(meta *netapi.StreamMeta) {
	defer meta.Src.Close()
	if !meta.DnsRequest {
		h.tcp <- struct{}{}
		_, _ = io.Copy(meta.Src, meta.Src)
		return
	}
	h.dnsTCP <- struct{}{}
	var length [2]byte
	if _, err := io.ReadFull(meta.Src, length[:]); err != nil {
		h.dnsErrors <- err
		return
	}
	query := make([]byte, int(length[0])<<8|int(length[1]))
	if _, err := io.ReadFull(meta.Src, query); err != nil {
		h.dnsErrors <- err
		return
	}
	response, err := sshTestDNSResponse(query)
	if err != nil {
		h.dnsErrors <- err
		return
	}
	length[0], length[1] = byte(len(response)>>8), byte(len(response))
	if _, err := meta.Src.Write(length[:]); err != nil {
		h.dnsErrors <- err
		return
	}
	if _, err := meta.Src.Write(response); err != nil {
		h.dnsErrors <- err
	}
}

func (h *sshServerTestHandler) HandlePacket(packet *netapi.Packet) {
	defer packet.DecRef()
	payload := packet.GetPayload()
	if packet.IsDNSRequest() {
		h.dnsUDP <- struct{}{}
		response, err := sshTestDNSResponse(payload)
		if err != nil {
			h.dnsErrors <- err
			return
		}
		if _, err := packet.WriteBack(response, packet.Dst()); err != nil {
			h.dnsErrors <- err
		}
		return
	}
	h.udp <- struct{}{}
	if _, err := packet.WriteBack(payload, packet.Dst()); err != nil {
		h.dnsErrors <- err
	}
}

func (*sshServerTestHandler) HandlePing(*netapi.PingMeta) {}

func sshTestDNSResponse(wire []byte) ([]byte, error) {
	request := &dns.Msg{Data: wire}
	if err := request.Unpack(); err != nil {
		return nil, fmt.Errorf("unpack DNS query: %w", err)
	}
	response := new(dns.Msg)
	dnsutil.SetReply(response, request)
	response.RecursionAvailable = true
	for _, question := range request.Question {
		if question.Header().Name != sshDNSName || question.Header().Class != dns.ClassINET {
			continue
		}
		switch dns.RRToType(question) {
		case dns.TypeA:
			response.Answer = append(response.Answer, &dns.A{
				Hdr:  dns.Header{Name: question.Header().Name, Class: dns.ClassINET, TTL: 30},
				Addr: netip.MustParseAddr(sshDNSIPv4),
			})
		case dns.TypeAAAA:
			response.Answer = append(response.Answer, &dns.AAAA{
				Hdr:  dns.Header{Name: question.Header().Name, Class: dns.ClassINET, TTL: 30},
				Addr: netip.MustParseAddr(sshDNSIPv6),
			})
		}
	}
	if err := response.Pack(); err != nil {
		return nil, fmt.Errorf("pack DNS response: %w", err)
	}
	return response.Data, nil
}

func newSSHServerTestIdentity(tb testing.TB) (Config, gossh.Signer) {
	tb.Helper()
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(hostPrivate)
	if err != nil {
		tb.Fatal(err)
	}
	_, userPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	userSigner, err := gossh.NewSignerFromKey(userPrivate)
	if err != nil {
		tb.Fatal(err)
	}
	return Config{
		Listen:           "127.0.0.1:0",
		HostKey:          string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey})),
		Username:         "alice",
		AuthorizedKey:    string(gossh.MarshalAuthorizedKey(userSigner.PublicKey())),
		UID:              65534,
		GID:              65534,
		AllowUnsafeShell: true,
	}, userSigner
}

func startSSHServerTestServer(tb testing.TB, config Config, handler netapi.Handler) *Server {
	tb.Helper()
	server, err := NewServer(config, handler)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() {
		if err := server.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			tb.Errorf("close SSH server: %v", err)
		}
	})
	return server
}

func sshClientConfig(username string, signer gossh.Signer) *gossh.ClientConfig {
	return &gossh.ClientConfig{
		User:            username,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
}

func dialSSHServer(tb testing.TB, server *Server, username string, signer gossh.Signer) *gossh.Client {
	tb.Helper()
	client, err := newSSHServerClient(server, username, signer)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = client.Close() })
	return client
}

func newSSHServerClient(server *Server, username string, signer gossh.Signer) (*gossh.Client, error) {
	conn, err := net.DialTimeout("tcp", server.listener.Addr().String(), 5*time.Second)
	if err != nil {
		return nil, err
	}
	clientConn, channels, requests, err := gossh.NewClientConn(conn, server.listener.Addr().String(), sshClientConfig(username, signer))
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("authenticate SSH client: %w", err)
	}
	return gossh.NewClient(clientConn, channels, requests), nil
}

func trySSHServerAuth(tb testing.TB, server *Server, username string, signer gossh.Signer) error {
	tb.Helper()
	conn, err := net.DialTimeout("tcp", server.listener.Addr().String(), 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	clientConn, channels, requests, err := gossh.NewClientConn(conn, server.listener.Addr().String(), sshClientConfig(username, signer))
	if err != nil {
		return err
	}
	return gossh.NewClient(clientConn, channels, requests).Close()
}

func TestSSHServerPublicKeyAndForwardingPolicy(t *testing.T) {
	config, authorizedSigner := newSSHServerTestIdentity(t)
	server := startSSHServerTestServer(t, config, newSSHServerTestHandler())
	client := dialSSHServer(t, server, config.Username, authorizedSigner)

	if _, err := client.Dial("tcp", "127.0.0.1:80"); err == nil {
		t.Fatal("direct-tcpip forwarding was accepted")
	}
	if err := trySSHServerAuth(t, server, "mallory", authorizedSigner); err == nil {
		t.Fatal("a different username authenticated with the authorized key")
	}
	_, unauthorizedPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unauthorizedSigner, err := gossh.NewSignerFromKey(unauthorizedPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if err := trySSHServerAuth(t, server, config.Username, unauthorizedSigner); err == nil {
		t.Fatal("an unauthorized public key authenticated")
	}
}

func TestSSHServerClosesIncompleteHandshake(t *testing.T) {
	config, _ := newSSHServerTestIdentity(t)
	server := startSSHServerTestServer(t, config, newSSHServerTestHandler())
	conn, err := net.DialTimeout("tcp", server.listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	closed := make(chan error, 1)
	go func() { closed <- server.Close() }()
	select {
	case err := <-closed:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("close server with incomplete handshake: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server shutdown waited for the SSH handshake deadline")
	}
}

func TestSSHServerProbeHelper(t *testing.T) {
	mode := os.Getenv(sshHelperModeEnv)
	if mode == "" {
		t.Skip("SSH server integration helper")
	}
	if mode != "network" {
		t.Fatalf("unknown SSH helper mode %q", mode)
	}
	if err := verifySSHNamespace(); err != nil {
		t.Fatal(err)
	}
	for _, probe := range []struct {
		network string
		address string
		payload []byte
	}{
		{"tcp", os.Getenv("YUH_SSH_SERVER_TCP4"), []byte("ssh-tcp-v4")},
		{"tcp", os.Getenv("YUH_SSH_SERVER_TCP6"), []byte("ssh-tcp-v6")},
		{"udp", os.Getenv("YUH_SSH_SERVER_UDP4"), []byte("ssh-udp-v4")},
		{"udp", os.Getenv("YUH_SSH_SERVER_UDP6"), []byte("ssh-udp-v6")},
	} {
		if err := sshServerEchoProbe(t, probe.network, probe.address, probe.payload); err != nil {
			t.Fatal(err)
		}
	}

	resolver := &net.Resolver{PreferGo: true}
	addresses, err := resolver.LookupIPAddr(t.Context(), "network-space.ssh.test")
	if err != nil {
		t.Fatalf("resolve through the isolated DNS gateway: %v", err)
	}
	var gotIPv4, gotIPv6 bool
	for _, address := range addresses {
		gotIPv4 = gotIPv4 || address.IP.Equal(net.ParseIP(sshDNSIPv4))
		gotIPv6 = gotIPv6 || address.IP.Equal(net.ParseIP(sshDNSIPv6))
	}
	if !gotIPv4 || !gotIPv6 {
		t.Fatalf("DNS returned incomplete A/AAAA records: %v", addresses)
	}

	query := dns.NewMsg(sshDNSName, dns.TypeA)
	response, err := dns.Exchange(t.Context(), query, "tcp", os.Getenv("YUH_SSH_SERVER_DNS4"))
	if err != nil {
		t.Fatalf("DNS-over-TCP through the isolated gateway: %v", err)
	}
	if len(response.Answer) != 1 || dns.RRToType(response.Answer[0]) != dns.TypeA {
		t.Fatalf("unexpected DNS-over-TCP response: %v", response)
	}
	if _, err := fmt.Fprintf(os.Stdout, "YUH_SSH_NETNS=%s\n", mustReadSSHNetNS(t)); err != nil {
		t.Fatal(err)
	}
}

func verifySSHNamespace() error {
	resolver, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return fmt.Errorf("read isolated resolver configuration: %w", err)
	}
	if !bytes.Contains(resolver, []byte("172.31.254.1")) {
		return fmt.Errorf("isolated resolver does not point at the Yuhaiin gateway: %q", resolver)
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("list isolated interfaces: %w", err)
	}
	var gotIPv4, gotIPv6 bool
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			return fmt.Errorf("read addresses on %s: %w", iface.Name, err)
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				continue
			}
			gotIPv4 = gotIPv4 || prefix.Addr() == netip.MustParseAddr("172.31.254.2")
			gotIPv6 = gotIPv6 || prefix.Addr() == netip.MustParseAddr("fd42:7d2a:9b31::2")
		}
	}
	if !gotIPv4 || !gotIPv6 {
		return fmt.Errorf("isolated link addresses missing: IPv4=%v IPv6=%v", gotIPv4, gotIPv6)
	}
	return nil
}

func sshServerEchoProbe(tb testing.TB, network, address string, payload []byte) error {
	tb.Helper()
	ctx, cancel := context.WithTimeout(tb.Context(), 5*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return fmt.Errorf("dial %s %s: %w", network, address, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("write %s %s: %w", network, address, err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("read %s %s: %w", network, address, err)
	}
	if !bytes.Equal(response, payload) {
		return fmt.Errorf("%s %s returned %q, want %q", network, address, response, payload)
	}
	return nil
}

func mustReadSSHNetNS(tb testing.TB) string {
	tb.Helper()
	namespace, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		tb.Fatal(err)
	}
	return namespace
}

func sshServerTestBinary(tb testing.TB) string {
	tb.Helper()
	executable, err := os.Executable()
	if err != nil {
		tb.Fatal(err)
	}
	data, err := os.ReadFile(executable)
	if err != nil {
		tb.Fatal(err)
	}
	directory, err := os.MkdirTemp("/tmp", "yuhaiin-sshserver-test-")
	if err != nil {
		tb.Fatal(err)
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		tb.Fatal(err)
	}
	binary := filepath.Join(directory, "sshserver.test")
	if err := os.WriteFile(binary, data, 0o755); err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = os.RemoveAll(directory) })
	return binary
}

func sshShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func sshNetworkProbeCommand(binary string) string {
	assignments := []struct{ name, value string }{
		{sshHelperModeEnv, "network"},
		{"YUH_SSH_SERVER_TCP4", "203.0.113.9:18080"},
		{"YUH_SSH_SERVER_TCP6", "[2001:db8::9]:18080"},
		{"YUH_SSH_SERVER_UDP4", "203.0.113.9:18080"},
		{"YUH_SSH_SERVER_UDP6", "[2001:db8::9]:18080"},
		{"YUH_SSH_SERVER_DNS4", "172.31.254.1:53"},
	}
	var command strings.Builder
	for _, assignment := range assignments {
		fmt.Fprintf(&command, "%s=%s ", assignment.name, sshShellQuote(assignment.value))
	}
	fmt.Fprintf(&command, "%s -test.run='^TestSSHServerProbeHelper$' -test.v", sshShellQuote(binary))
	return command.String()
}

func TestSSHServerNetworkIntegration(t *testing.T) {
	if os.Getenv(sshIntegrationEnv) != "1" {
		t.Skip("set " + sshIntegrationEnv + "=1 on a Linux host with TUN and network namespace privileges")
	}
	config, userSigner := newSSHServerTestIdentity(t)
	config.IPv6 = true
	handler := newSSHServerTestHandler()
	server := startSSHServerTestServer(t, config, handler)
	client := dialSSHServer(t, server, config.Username, userSigner)
	binary := sshServerTestBinary(t)

	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	output, err := session.CombinedOutput(sshNetworkProbeCommand(binary))
	_ = session.Close()
	if err != nil {
		t.Fatalf("isolated IPv4/IPv6, TCP/UDP and DNS probe failed: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("YUH_SSH_NETNS=net:[")) {
		t.Fatalf("probe did not report its isolated network namespace: %s", output)
	}
	if namespace := mustReadSSHNetNS(t); strings.Contains(string(output), "YUH_SSH_NETNS="+namespace) {
		t.Fatalf("SSH command remained in the host network namespace %s", namespace)
	}
	for name, channel := range map[string]<-chan struct{}{
		"routed TCP":   handler.tcp,
		"routed UDP":   handler.udp,
		"DNS over TCP": handler.dnsTCP,
		"DNS over UDP": handler.dnsUDP,
	} {
		select {
		case <-channel:
		default:
			t.Errorf("network handler did not receive %s traffic", name)
		}
	}
	select {
	case err := <-handler.dnsErrors:
		t.Fatalf("DNS handler failed: %v", err)
	default:
	}
}

func TestSSHServerSharesOnlyWithinConnection(t *testing.T) {
	if os.Getenv(sshIntegrationEnv) != "1" {
		t.Skip("set " + sshIntegrationEnv + "=1 on a Linux host with TUN and network namespace privileges")
	}
	config, userSigner := newSSHServerTestIdentity(t)
	server := startSSHServerTestServer(t, config, newSSHServerTestHandler())
	first := dialSSHServer(t, server, config.Username, userSigner)
	second := dialSSHServer(t, server, config.Username, userSigner)

	firstKeeper, firstNS := startSSHNamespaceKeeper(t, first)
	defer firstKeeper.Close()
	secondKeeper, secondNS := startSSHNamespaceKeeper(t, first)
	defer secondKeeper.Close()
	if firstNS != secondNS {
		t.Fatalf("concurrent commands on one SSH connection used different namespaces: %s != %s", firstNS, secondNS)
	}
	otherKeeper, otherNS := startSSHNamespaceKeeper(t, second)
	defer otherKeeper.Close()
	if firstNS == otherNS {
		t.Fatalf("separate SSH connections shared network namespace %s", firstNS)
	}

	if err := firstKeeper.Close(); err != nil {
		t.Fatalf("close first shared command: %v", err)
	}
	_ = firstKeeper.Wait()
	client, err := first.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	output, err := client.CombinedOutput("readlink /proc/self/ns/net")
	_ = client.Close()
	if err != nil {
		t.Fatalf("start a command after the previous network lease was released: %v", err)
	}
	if strings.TrimSpace(string(output)) != firstNS {
		t.Fatalf("namespace closed while another command still held a lease: got %q, want %q", strings.TrimSpace(string(output)), firstNS)
	}

	if err := secondKeeper.Close(); err != nil {
		t.Fatalf("close last shared command: %v", err)
	}
	_ = secondKeeper.Wait()
	restarted := runSSHCommand(t, first, "readlink /proc/self/ns/net")
	if strings.TrimSpace(string(restarted)) == firstNS {
		t.Fatalf("a later command reused a namespace after the final lease closed: %q", restarted)
	}
}

func startSSHNamespaceKeeper(t testing.TB, client *gossh.Client) (*gossh.Session, string) {
	t.Helper()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()
		t.Fatal(err)
	}
	if err := session.Start("readlink /proc/self/ns/net; exec sleep 30"); err != nil {
		_ = session.Close()
		t.Fatal(err)
	}
	line := make(chan struct {
		namespace string
		err       error
	}, 1)
	go func() {
		namespace, err := bufio.NewReader(stdout).ReadString('\n')
		line <- struct {
			namespace string
			err       error
		}{namespace: strings.TrimSpace(namespace), err: err}
	}()
	select {
	case result := <-line:
		if result.err != nil {
			_ = session.Close()
			t.Fatalf("read namespace from SSH command: %v", result.err)
		}
		if !strings.HasPrefix(result.namespace, "net:[") {
			_ = session.Close()
			t.Fatalf("unexpected network namespace identifier %q", result.namespace)
		}
		return session, result.namespace
	case <-time.After(5 * time.Second):
		_ = session.Close()
		t.Fatal("SSH command did not start in its network namespace")
		return nil, ""
	}
}

func runSSHCommand(tb testing.TB, client *gossh.Client, command string) []byte {
	tb.Helper()
	session, err := client.NewSession()
	if err != nil {
		tb.Fatal(err)
	}
	defer session.Close()
	output, err := session.CombinedOutput(command)
	if err != nil {
		tb.Fatalf("run SSH command %q: %v\n%s", command, err, output)
	}
	return output
}
