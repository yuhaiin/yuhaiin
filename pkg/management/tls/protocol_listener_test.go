package tls

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"sync"
	"testing"
	"time"
)

type sharedPortServer struct {
	address     string
	certificate tls.Certificate
	listener    *protocolListener
	server      *http.Server
	done        chan error
}

func startSharedPortServer(t *testing.T, sniffTimeout time.Duration, server *http.Server) *sharedPortServer {
	t.Helper()
	certificate, _, _, err := LoadOrCreate(t.TempDir(), []string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	config := ServerConfig(certificate)
	listener := newProtocolListener(raw, config, sniffTimeout)
	if server == nil {
		server = &http.Server{}
	}
	if server.Handler == nil {
		server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			_, _ = fmt.Fprintf(w, "%s %s", scheme, r.Proto)
		})
	}
	server.TLSConfig = config
	result := &sharedPortServer{
		address:     raw.Addr().String(),
		certificate: certificate,
		listener:    listener,
		server:      server,
		done:        make(chan error, 1),
	}
	go func() { result.done <- server.Serve(listener) }()
	t.Cleanup(result.stop(t))
	return result
}

func (s *sharedPortServer) stop(t *testing.T) func() {
	return func() {
		_ = s.server.Close()
		select {
		case err := <-s.done:
			if !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("HTTP server returned %v after close", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("HTTP server did not stop")
		}
	}
}

func (s *sharedPortServer) client(t *testing.T, http2 bool) *http.Client {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(s.certificate.Leaf)
	transport := &http.Transport{
		Proxy:             nil,
		TLSClientConfig:   &tls.Config{RootCAs: roots, ServerName: "127.0.0.1"},
		ForceAttemptHTTP2: http2,
	}
	if !http2 {
		transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func get(t *testing.T, client *http.Client, url string) (string, *http.Response) {
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
	return string(body), response
}

func TestProtocolListenerServesHTTPAndHTTPSOnOnePort(t *testing.T) {
	server := startSharedPortServer(t, ProtocolSniffTimeout, nil)

	if body, _ := get(t, server.client(t, false), "http://"+server.address+"/"); body != "http HTTP/1.1" {
		t.Fatalf("cleartext response = %q", body)
	}

	body, response := get(t, server.client(t, false), "https://"+server.address+"/")
	if body != "https HTTP/1.1" {
		t.Fatalf("HTTPS HTTP/1.1 response = %q", body)
	}
	if state := response.TLS; state == nil || state.Version < tls.VersionTLS12 || state.NegotiatedProtocol != "http/1.1" {
		t.Fatalf("HTTPS HTTP/1.1 connection state = %+v", state)
	}

	body, response = get(t, server.client(t, true), "https://"+server.address+"/")
	if body != "https HTTP/2.0" || response.ProtoMajor != 2 {
		t.Fatalf("HTTPS HTTP/2 response = %q (%s)", body, response.Proto)
	}
	if response.TLS.NegotiatedProtocol != "h2" {
		t.Fatalf("ALPN = %q, want h2", response.TLS.NegotiatedProtocol)
	}

	// Cleartext still works after TLS clients used the same port.
	if body, _ := get(t, server.client(t, false), "http://"+server.address+"/"); body != "http HTTP/1.1" {
		t.Fatalf("cleartext response after HTTPS = %q", body)
	}
}

func TestProtocolListenerRejectsTLSBelow12(t *testing.T) {
	server := startSharedPortServer(t, ProtocolSniffTimeout, nil)
	conn, err := tls.Dial("tcp", server.address, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // the test checks protocol negotiation only.
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS11,
	})
	if err == nil {
		_ = conn.Close()
		t.Fatal("TLS 1.1 handshake succeeded")
	}
}

func TestIsTLSClientHello(t *testing.T) {
	if !IsTLSClientHello([]byte{0x16, 0x03, 0x01}) {
		t.Fatal("TLS ClientHello prefix was not recognized")
	}
	for _, prefix := range [][]byte{{0x47, 0x45, 0x54}, {0x50, 0x52, 0x49}, {0x16, 0x02, 0x01}, {0x16, 0x03}, nil} {
		if IsTLSClientHello(prefix) {
			t.Errorf("non-TLS prefix %x was recognized", prefix)
		}
	}
}

func pendingCount(l *protocolListener) int {
	l.pendingMu.Lock()
	defer l.pendingMu.Unlock()
	return len(l.pending)
}

func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func assertClosedByPeer(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(conn); err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			t.Fatal("connection stayed open")
		}
	}
}

func TestProtocolListenerCloseClosesUnclassifiedConnections(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	protocolListener := newProtocolListener(listener, &tls.Config{}, ProtocolSniffTimeout)
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	waitFor(t, "classification to begin", func() bool { return pendingCount(protocolListener) == 1 })

	if err := protocolListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	assertClosedByPeer(t, client)
	if _, err := protocolListener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close returned %v, want net.ErrClosed", err)
	}
	if err := protocolListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second Close returned %v", err)
	}
	if _, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second); err == nil {
		t.Fatal("port still accepts connections after Close")
	}
}

func TestProtocolListenerDropsIncompleteClientHello(t *testing.T) {
	server := startSharedPortServer(t, 50*time.Millisecond, nil)

	// Only two bytes of a record header: classification cannot finish and the
	// sniff deadline must close the connection.
	conn, err := net.Dial("tcp", server.address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{0x16, 0x03}); err != nil {
		t.Fatal(err)
	}
	assertClosedByPeer(t, conn)
	waitFor(t, "pending connection cleanup", func() bool { return pendingCount(server.listener) == 0 })

	// The listener keeps serving after dropping the incomplete handshake.
	if body, _ := get(t, server.client(t, true), "https://"+server.address+"/"); body != "https HTTP/2.0" {
		t.Fatalf("HTTPS response after incomplete handshake = %q", body)
	}
}

func TestProtocolListenerTruncatedHandshakeUsesServerTimeout(t *testing.T) {
	server := startSharedPortServer(t, ProtocolSniffTimeout, &http.Server{ReadHeaderTimeout: 100 * time.Millisecond})

	// A full record-header prefix is classified as TLS; the truncated body then
	// stalls in the handshake, which net/http bounds with ReadHeaderTimeout.
	conn, err := net.Dial("tcp", server.address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01}); err != nil {
		t.Fatal(err)
	}
	assertClosedByPeer(t, conn)
}

func TestProtocolListenerSniffTimeoutRacesClose(t *testing.T) {
	baseline := runtime.NumGoroutine()
	for range 20 {
		raw, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listener := newProtocolListener(raw, &tls.Config{}, 5*time.Millisecond)
		acceptDone := make(chan error, 1)
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					acceptDone <- err
					return
				}
				_ = conn.Close()
			}
		}()

		var clients []net.Conn
		var mu sync.Mutex
		var wg sync.WaitGroup
		for i := range 16 {
			wg.Go(func() {
				conn, err := net.Dial("tcp", raw.Addr().String())
				if err != nil {
					return // the listener may already be closed
				}
				switch i % 3 {
				case 1:
					_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
				case 2:
					_, _ = conn.Write([]byte{0x16})
				}
				mu.Lock()
				clients = append(clients, conn)
				mu.Unlock()
			})
		}
		// Close around the moment the sniff deadlines expire.
		time.Sleep(5 * time.Millisecond)
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
		wg.Wait()
		if err := <-acceptDone; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept returned %v after Close", err)
		}
		for _, conn := range clients {
			assertClosedByPeer(t, conn)
			_ = conn.Close()
		}
		if n := pendingCount(listener); n != 0 {
			t.Fatalf("%d connections remain pending after Close", n)
		}
	}
	waitFor(t, "classifier goroutines to exit", func() bool { return runtime.NumGoroutine() <= baseline })
}

// Bytes peeked during classification must reach net/http untouched.
func TestProtocolListenerPassesCleartextBytesThrough(t *testing.T) {
	server := startSharedPortServer(t, ProtocolSniffTimeout, nil)
	conn, err := net.Dial("tcp", server.address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET /x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if string(body) != "http HTTP/1.1" {
		t.Fatalf("raw cleartext response = %q", body)
	}
}
