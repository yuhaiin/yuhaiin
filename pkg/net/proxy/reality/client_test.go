package reality

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	utls "github.com/refraction-networking/utls"
	realitytls "github.com/xtls/reality"
)

func TestClient(t *testing.T) {
	// REALITY needs a TLS 1.3 decoy handshake even for an authenticated
	// connection. Keep that dependency on loopback with an ephemeral port.
	decoy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	decoy.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	decoy.StartTLS()
	t.Cleanup(decoy.Close)

	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := fixed.NewServer(fixed.ServerConfig{
		Host: "127.0.0.1:0", Control: fixed.ControlDisableUDP,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	address, ok := lis.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatal("REALITY listener did not bind a TCP address")
	}
	rlis, err := NewServer(ServerConfig{
		Dest: decoy.Listener.Addr().String(), ShortID: []string{"123456"},
		ServerName: []string{"example.com"},
		PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()),
	}, lis)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rlis.Close() })
	// NewListener initializes this cache asynchronously. An immediate client
	// otherwise enters the upstream five-second polling loop before the local
	// probe completes. Await real initialization rather than sleeping or
	// installing synthetic cache entries.
	ready, stopReady := context.WithTimeout(t.Context(), 5*time.Second)
	defer stopReady()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for alpn := range 3 {
		cacheKey := decoy.Listener.Addr().String() + " example.com " + strconv.Itoa(alpn)
		for {
			value, _ := realitytls.GlobalPostHandshakeRecordsLens.Load(cacheKey)
			if _, ok := value.([]int); ok {
				break
			}
			select {
			case <-tick.C:
			case <-ready.Done():
				t.Fatal("local REALITY decoy initialization timed out")
			}
		}
	}

	payload := []byte("local REALITY authenticated echo")
	result := make(chan error, 1)
	go func() {
		conn, err := rlis.Accept()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			result <- err
			return
		}
		_, err = io.CopyN(conn, conn, int64(len(payload)))
		result <- err
	}()

	pp, err := fixed.NewClient(fixed.Config{Host: "127.0.0.1", Port: int32(address.Port)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pp, err = NewClient(Config{
		ServerName: "example.com", ShortID: "123456",
		PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()),
	}, pp)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn, err := pp.Conn(ctx, netapi.EmptyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("write echo: bytes=%d err=%v", n, err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatal("REALITY echo payload differs")
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestRealityClientRejectsInvalidPublicKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
	}{
		{name: "invalid base64", key: "!"},
		{name: "empty public key", key: ""},
		{name: "short public key", key: base64.RawURLEncoding.EncodeToString(make([]byte, 31))},
		{name: "long public key", key: base64.RawURLEncoding.EncodeToString(make([]byte, 33))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewClient(Config{PublicKey: tc.key}, nil); err == nil {
				t.Fatal("expected invalid public key error")
			}
		})
	}
}

func TestRealityVerifierRejectsMissingCertificates(t *testing.T) {
	v := &realityVerifier{serverName: "example.com"}
	if err := v.VerifyConnection(utls.ConnectionState{}); err == nil {
		t.Fatal("expected certificate validation error")
	}
	if v.verified {
		t.Fatal("missing certificate marked as verified")
	}
}

func TestRealityVerifierHMACSignature(t *testing.T) {
	authKey := []byte("test-reality-auth-key-32-bytes!!!!")
	certificate := realityHMACTestCertificate(t, authKey)
	parsed, err := x509.ParseCertificate(certificate)
	if err != nil {
		t.Fatal(err)
	}
	state := utls.ConnectionState{PeerCertificates: []*x509.Certificate{parsed}}
	v := &realityVerifier{serverName: "example.com", authKey: authKey}
	if err := v.VerifyConnection(state); err != nil {
		t.Fatalf("valid REALITY certificate rejected: %v", err)
	}
	if !v.verified {
		t.Fatal("valid REALITY certificate not verified")
	}

	v = &realityVerifier{serverName: "example.com", authKey: []byte("different auth key")}
	if err := v.VerifyConnection(state); err == nil {
		t.Fatal("certificate with invalid REALITY signature accepted")
	}
	if v.verified {
		t.Fatal("invalid signature marked as verified")
	}
}

func realityHMACTestCertificate(t *testing.T, authKey []byte) []byte {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	// REALITY replaces the certificate signature with an HMAC over the
	// ephemeral Ed25519 public key.
	var encoded struct {
		TBS                asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		SignatureValue     asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &encoded); err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha512.New, authKey)
	_, _ = mac.Write(publicKey)
	sig := mac.Sum(nil)
	encoded.SignatureValue = asn1.BitString{Bytes: sig, BitLength: len(sig) * 8}
	der, err = asn1.Marshal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestRealityClientFallbackSendsDecoyRequest(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	result := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(serverConn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			result <- err
			return
		}
		if req.Method != http.MethodGet || req.Host != "example.com" {
			result <- fmt.Errorf("unexpected decoy request: %s %s", req.Method, req.Host)
			return
		}
		if _, err := io.WriteString(serverConn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"); err != nil {
			result <- err
			return
		}
		result <- nil
	}()

	realityClientFallback(clientConn, "example.com", utls.HelloChrome_Auto)
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("decoy request did not complete")
	}
	var b [1]byte
	_ = serverConn.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := serverConn.Read(b[:]); n != 0 || err != io.EOF {
		t.Fatalf("fallback left client connection open: n=%d, err=%v", n, err)
	}
}

func TestRealityVerifierRejectsUntrustedChain(t *testing.T) {
	der := realityHMACTestCertificate(t, []byte("correct-auth"))
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	v := &realityVerifier{serverName: "example.com", authKey: []byte("wrong-auth")}
	if err := v.VerifyConnection(utls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf, leaf},
	}); err == nil {
		t.Fatal("expected an untrusted certificate chain error")
	}
	if v.verified {
		t.Fatal("untrusted certificate marked as verified")
	}
}
