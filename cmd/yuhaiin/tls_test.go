package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	managementtls "github.com/Asutorufa/yuhaiin/pkg/management/tls"
)

func TestHTTPAndHTTPSShareOnePort(t *testing.T) {
	certificate, _, _, err := managementtls.LoadOrCreate(t.TempDir(), []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	protocolListener := newProtocolListener(listener, tlsConfig)
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil {
				_, _ = w.Write([]byte("http"))
				return
			}
			_, _ = w.Write([]byte("https"))
		}),
		TLSConfig: tlsConfig,
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(protocolListener) }()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case err := <-serveDone:
			if !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("HTTP server returned %v after close", err)
			}
		case <-time.After(time.Second):
			t.Error("HTTP server did not stop")
		}
	})

	address := listener.Addr().String()
	plainClient := &http.Client{Transport: &http.Transport{Proxy: nil}}
	t.Cleanup(plainClient.CloseIdleConnections)
	plainResponse, err := plainClient.Get("http://" + address + "/")
	if err != nil {
		t.Fatal(err)
	}
	plainBody, err := io.ReadAll(plainResponse.Body)
	_ = plainResponse.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(plainBody) != "http" {
		t.Fatalf("plain HTTP response = %q, want %q", plainBody, "http")
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(certificate.Leaf)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    rootCAs,
			ServerName: "localhost",
		},
		ForceAttemptHTTP2: true,
	}}
	t.Cleanup(client.CloseIdleConnections)
	secureResponse, err := client.Get("https://" + address + "/")
	if err != nil {
		t.Fatal(err)
	}
	secureBody, err := io.ReadAll(secureResponse.Body)
	_ = secureResponse.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(secureBody) != "https" {
		t.Fatalf("HTTPS response = %q, want %q", secureBody, "https")
	}
	if secureResponse.ProtoMajor != 2 {
		t.Fatalf("HTTPS protocol = %q, want HTTP/2", secureResponse.Proto)
	}
}

func TestRemoteHTTPStaticRequestsRedirectToHTTPS(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	redirector := redirectRemoteHTTPToHTTPS(handler, &net.TCPAddr{IP: net.IPv4zero, Port: 50051})

	tests := []struct {
		name       string
		method     string
		path       string
		remoteAddr string
		wantStatus int
		wantTarget string
	}{
		{
			name:       "remote page request",
			method:     http.MethodGet,
			path:       "/settings?tab=routes",
			remoteAddr: "192.0.2.10:43210",
			wantStatus: http.StatusTemporaryRedirect,
			wantTarget: "https://admin.example:50051/settings?tab=routes",
		},
		{
			name:       "remote api request is not redirected",
			method:     http.MethodGet,
			path:       "/api/v2/auth/setup",
			remoteAddr: "192.0.2.10:43210",
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "remote post body is not redirected",
			method:     http.MethodPost,
			path:       "/login",
			remoteAddr: "192.0.2.10:43210",
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "loopback page remains http",
			method:     http.MethodGet,
			path:       "/",
			remoteAddr: "127.0.0.1:43210",
			wantStatus: http.StatusNoContent,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(tt.method, "http://admin.example:50051"+tt.path, nil)
			request.RemoteAddr = tt.remoteAddr
			response := httptest.NewRecorder()
			redirector.ServeHTTP(response, request)
			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, tt.wantStatus)
			}
			if location := response.Header().Get("Location"); location != tt.wantTarget {
				t.Fatalf("Location = %q, want %q", location, tt.wantTarget)
			}
		})
	}
}

func TestIsTLSClientHello(t *testing.T) {
	if !isTLSClientHello([]byte{0x16, 0x03, 0x01}) {
		t.Fatal("TLS ClientHello prefix was not recognized")
	}
	for _, prefix := range [][]byte{{0x47, 0x45, 0x54}, {0x50, 0x52, 0x49}, {0x16, 0x02, 0x01}, {0x16, 0x03}} {
		if isTLSClientHello(prefix) {
			t.Errorf("non-TLS prefix %x was recognized", prefix)
		}
	}
}

func TestProtocolListenerCloseClosesUnclassifiedConnections(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	protocolListener := newProtocolListener(listener, &tls.Config{})
	t.Cleanup(func() { _ = protocolListener.Close() })
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	deadline := time.Now().Add(time.Second)
	for {
		protocolListener.pendingMu.Lock()
		pending := len(protocolListener.pending)
		protocolListener.pendingMu.Unlock()
		if pending == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("listener did not begin classifying the connection")
		}
		time.Sleep(time.Millisecond)
	}

	if err := protocolListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("client connection remained open after listener close")
	}
}
