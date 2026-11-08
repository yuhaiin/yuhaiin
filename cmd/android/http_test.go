package yuhaiin

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

type androidHTTPTestServer struct {
	server   *http.Server
	listener net.Listener
	port     int
	tls      bool
	done     chan error
}

// startAndroidHTTP mirrors App.Start: bind with listenAndroidHTTP, then serve
// with newAndroidHTTPServer.
func startAndroidHTTP(t *testing.T) *androidHTTPTestServer {
	t.Helper()
	lis, err := listenAndroidHTTP()
	if err != nil {
		t.Fatal(err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		_, _ = fmt.Fprintf(w, "%s %s %s", scheme, r.Proto, r.URL.Path)
	})
	server, serverListener := newAndroidHTTPServer(handler, lis)
	result := &androidHTTPTestServer{server: server, listener: serverListener, port: listenerPort(t, lis), tls: server.TLSConfig != nil, done: make(chan error, 1)}
	go func() { result.done <- server.Serve(serverListener) }()
	t.Cleanup(func() { _ = result.stop() })
	return result
}

func (s *androidHTTPTestServer) stop() error {
	_ = s.server.Close()
	select {
	case err := <-s.done:
		s.done <- err
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-time.After(2 * time.Second):
		return errors.New("android HTTP server did not stop")
	}
}

func setupAndroidHTTP(t *testing.T, allowLAN bool) string {
	t.Helper()
	SetSavePath(t.TempDir())
	tlsDir := filepath.Join(t.TempDir(), "management-tls")
	SetManagementTLSDir(tlsDir)
	t.Cleanup(func() { SetManagementTLSDir("") })
	GetStore().PutBoolean(AllowLanKey, allowLAN)
	GetStore().PutInt(NewYuhaiinPortKey, -1)
	return tlsDir
}

func androidClient(t *testing.T, forceHTTP1 bool) *http.Client {
	t.Helper()
	transport := &http.Transport{
		Proxy:             nil,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed test certificate
		ForceAttemptHTTP2: !forceHTTP1,
	}
	if forceHTTP1 {
		transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func fetch(t *testing.T, client *http.Client, url string) (*http.Response, string) {
	t.Helper()
	response, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return response, string(body)
}

func TestAndroidHTTPServesHTTPAndHTTPSOnOnePort(t *testing.T) {
	setupAndroidHTTP(t, false)
	server := startAndroidHTTP(t)
	base := "127.0.0.1:" + strconv.Itoa(server.port)

	// The in-app WebView and API keep using cleartext loopback, unredirected.
	response, body := fetch(t, androidClient(t, true), "http://"+base+"/api/v2/status")
	if response.StatusCode != http.StatusOK || body != "http HTTP/1.1 /api/v2/status" {
		t.Fatalf("cleartext API = %d %q", response.StatusCode, body)
	}
	response, body = fetch(t, androidClient(t, true), "http://"+base+"/")
	if response.StatusCode != http.StatusOK || body != "http HTTP/1.1 /" {
		t.Fatalf("cleartext page = %d %q", response.StatusCode, body)
	}

	response, body = fetch(t, androidClient(t, true), "https://"+base+"/")
	if body != "https HTTP/1.1 /" || response.TLS.Version < tls.VersionTLS12 || response.TLS.NegotiatedProtocol != "http/1.1" {
		t.Fatalf("HTTPS HTTP/1.1 = %q %+v", body, response.TLS)
	}
	response, body = fetch(t, androidClient(t, false), "https://"+base+"/")
	if body != "https HTTP/2.0 /" || response.TLS.NegotiatedProtocol != "h2" {
		t.Fatalf("HTTPS HTTP/2 = %q (%s)", body, response.Proto)
	}
	if err := response.TLS.PeerCertificates[0].VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("certificate does not cover 127.0.0.1: %v", err)
	}
}

func TestAndroidHTTPKeepsLoopbackBindWithoutLAN(t *testing.T) {
	setupAndroidHTTP(t, false)
	server := startAndroidHTTP(t)
	address, ok := server.listener.Addr().(*net.TCPAddr)
	if !ok || !address.IP.IsLoopback() {
		t.Fatalf("listener address = %v, want loopback when LAN access is disabled", server.listener.Addr())
	}
}

func TestAndroidHTTPAllowsLANOnSamePort(t *testing.T) {
	setupAndroidHTTP(t, true)
	server := startAndroidHTTP(t)
	address, ok := server.listener.Addr().(*net.TCPAddr)
	if !ok || !address.IP.IsUnspecified() {
		t.Fatalf("listener address = %v, want all interfaces when LAN access is enabled", server.listener.Addr())
	}
	if got := GetStore().GetInt(NewYuhaiinPortKey); int(got) != server.port {
		t.Fatalf("persisted port = %d, want %d", got, server.port)
	}
	if _, body := fetch(t, androidClient(t, false), "https://127.0.0.1:"+strconv.Itoa(server.port)+"/"); body != "https HTTP/2.0 /" {
		t.Fatalf("HTTPS over the LAN listener = %q", body)
	}
}

func TestAndroidHTTPReusesCertificateAndReleasesPortOnStop(t *testing.T) {
	tlsDir := setupAndroidHTTP(t, false)
	baseline := runtime.NumGoroutine()

	first := startAndroidHTTP(t)
	_, _ = fetch(t, androidClient(t, false), "https://127.0.0.1:"+strconv.Itoa(first.port)+"/")
	firstCert, err := os.ReadFile(filepath.Join(tlsDir, "management-tls.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(tlsDir, "management-tls.pem")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("certificate bundle mode = %v, %v; want 0600", info.Mode().Perm(), err)
	}

	// Leave one connection mid-classification and one idle TLS connection.
	pending, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(first.port))
	if err != nil {
		t.Fatal(err)
	}
	defer pending.Close()
	idle, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(first.port), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()

	if err := first.stop(); err != nil {
		t.Fatal(err)
	}
	for _, conn := range []net.Conn{pending, idle} {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Fatal("connection stayed open after stop")
		} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			t.Fatal("connection stayed open after stop")
		}
	}

	// Reconnecting reuses the preferred port and the persisted certificate.
	second := startAndroidHTTP(t)
	if second.port != first.port {
		t.Fatalf("restart port = %d, want released port %d", second.port, first.port)
	}
	secondCert, err := os.ReadFile(filepath.Join(tlsDir, "management-tls.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if string(secondCert) != string(firstCert) {
		t.Fatal("certificate was regenerated on restart")
	}
	if err := second.stop(); err != nil {
		t.Fatal(err)
	}
	androidClient(t, false).CloseIdleConnections()

	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > baseline+2 { // allow for client transport goroutines winding down
		if time.Now().After(deadline) {
			t.Fatalf("goroutines = %d after stop, baseline %d", runtime.NumGoroutine(), baseline)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAndroidHTTPWithoutCertificateDirectoryStaysHTTP(t *testing.T) {
	setupAndroidHTTP(t, false)
	SetManagementTLSDir("")
	server := startAndroidHTTP(t)
	if server.tls {
		t.Fatal("TLS enabled without a certificate directory")
	}
	if _, body := fetch(t, androidClient(t, true), "http://127.0.0.1:"+strconv.Itoa(server.port)+"/"); body != "http HTTP/1.1 /" {
		t.Fatalf("cleartext response = %q", body)
	}
}

func TestAndroidHTTPFallsBackToHTTPWhenCertificateIsUnreadable(t *testing.T) {
	tlsDir := setupAndroidHTTP(t, false)
	if err := os.MkdirAll(tlsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tlsDir, "management-tls.pem"), []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := startAndroidHTTP(t)
	if server.tls {
		t.Fatal("TLS enabled with an unreadable certificate")
	}
	if _, body := fetch(t, androidClient(t, true), "http://127.0.0.1:"+strconv.Itoa(server.port)+"/"); body != "http HTTP/1.1 /" {
		t.Fatalf("cleartext response = %q", body)
	}
}
