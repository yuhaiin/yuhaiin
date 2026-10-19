package gateway

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	utls "github.com/refraction-networking/utls"
)

const encryptedClientHelloExtension uint16 = 0xfe0d

func TestHTTPSMITMAllowsECHGREASEAndFiltersPath(t *testing.T) {
	config := echPathGatewayConfig([]string{"example.com"}, "reject")
	m, _ := newTestManager(t, config, nil)
	address, workers := interceptListener(t, m, "example.com:443", "127.0.0.1:1")
	t.Cleanup(workers.Wait)
	roots := gatewayRootPool(t, m)

	raw, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	client := newGREASEECHClient(t, raw, "example.com", roots, []string{"http/1.1"})
	defer client.Close()
	if err := client.HandshakeContext(t.Context()); err != nil {
		counters := m.current.Load().gateways["g"].engine.Counters
		t.Fatalf("TLS handshake with GREASE ECH failed: %v (protocol failures=%d TLS failures=%d)", err, counters.ProtocolFailures.Load(), counters.TLSFailures.Load())
	}
	if client.ConnectionState().ECHAccepted {
		t.Fatal("GREASE ECH must not be reported as accepted ECH")
	}

	if _, err := io.WriteString(client, "GET /ads/banner HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("ad path status=%d, want %d", response.StatusCode, http.StatusNoContent)
	}

	counters := m.current.Load().gateways["g"].engine.Counters
	if got := counters.ProtocolFailures.Load(); got != 0 {
		t.Fatalf("protocol failures=%d, want 0 for valid GREASE ECH", got)
	}
	if got := counters.TLSFailures.Load(); got != 0 {
		t.Fatalf("TLS failures=%d, want 0", got)
	}
	if got := counters.Blocked.Load(); got != 1 {
		t.Fatalf("blocked requests=%d, want 1", got)
	}
}

func TestHTTPSMITMRealECHRejectionCanRetryWithoutECH(t *testing.T) {
	config := echPathGatewayConfig([]string{"secret.example"}, "reject")
	m, _ := newTestManager(t, config, nil)
	address, workers := interceptListener(t, m, "secret.example:443", "127.0.0.1:1", "public.example")
	t.Cleanup(workers.Wait)
	roots := gatewayRootPool(t, m)
	configList := testECHConfigList(t, "public.example")

	// The initial ECH handshake uses public.example as its visible outer SNI.
	// With no ECH private key configured, Gateway completes TLS on that outer
	// name and the client reports an ECH rejection before sending HTTP data.
	raw, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	first := tls.Client(raw, &tls.Config{
		MinVersion:                     tls.VersionTLS13,
		ServerName:                     "secret.example",
		RootCAs:                        roots,
		NextProtos:                     []string{"http/1.1"},
		EncryptedClientHelloConfigList: configList,
	})
	rejectionErr := first.HandshakeContext(t.Context())
	var rejection *tls.ECHRejectionError
	if !errors.As(rejectionErr, &rejection) {
		_ = first.Close()
		t.Fatalf("first handshake error=%v, want ECHRejectionError", rejectionErr)
	}
	if len(rejection.RetryConfigList) != 0 {
		_ = first.Close()
		t.Fatalf("retry config length=%d, want no retry configs from ECH-disabled server", len(rejection.RetryConfigList))
	}
	_ = first.Close()

	// A client following the ECH rejection signal retries the connection with
	// ECH disabled. That ClientHello exposes secret.example and can be filtered
	// by request path.
	raw, err = (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	retry := tls.Client(raw, &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: "secret.example",
		RootCAs:    roots,
		NextProtos: []string{"http/1.1"},
	})
	defer retry.Close()
	if err := retry.HandshakeContext(t.Context()); err != nil {
		t.Fatalf("ECH-disabled retry handshake failed: %v", err)
	}
	if _, err := io.WriteString(retry, "GET /ads/audio HTTP/1.1\r\nHost: secret.example\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(retry), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("ad path status=%d, want %d", response.StatusCode, http.StatusNoContent)
	}

	counters := m.current.Load().gateways["g"].engine.Counters
	if got := counters.ProtocolFailures.Load(); got != 0 {
		t.Fatalf("protocol failures=%d, want 0 for ECH rejection", got)
	}
	if got := counters.TLSFailures.Load(); got != 0 {
		t.Fatalf("TLS failures=%d, want 0", got)
	}
	if got := counters.Blocked.Load(); got != 1 {
		t.Fatalf("blocked requests=%d, want 1 after client retry", got)
	}
}

func TestHTTPSMITMECHOuterWithoutHTTPALPNStillRejects(t *testing.T) {
	config := echPathGatewayConfig([]string{"secret.example"}, "reject")
	m, _ := newTestManager(t, config, nil)
	address, workers := interceptListener(t, m, "secret.example:443", "127.0.0.1:1", "public.example")
	t.Cleanup(workers.Wait)
	raw, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	// The outer ALPN may be absent even when the encrypted inner handshake
	// carries HTTP ALPN. It must not prevent authenticated ECH rejection.
	client := tls.Client(raw, &tls.Config{
		MinVersion:                     tls.VersionTLS13,
		ServerName:                     "secret.example",
		RootCAs:                        gatewayRootPool(t, m),
		EncryptedClientHelloConfigList: testECHConfigList(t, "public.example"),
	})
	defer client.Close()
	var rejection *tls.ECHRejectionError
	if err := client.HandshakeContext(t.Context()); !errors.As(err, &rejection) {
		t.Fatalf("outer handshake error=%v, want ECHRejectionError", err)
	}
	counters := m.current.Load().gateways["g"].engine.Counters
	if got := counters.ProtocolFailures.Load(); got != 0 {
		t.Fatalf("protocol failures=%d, want 0", got)
	}
	if got := counters.TLSFailures.Load(); got != 0 {
		t.Fatalf("TLS failures=%d, want 0", got)
	}
}

func TestHTTPSMITMECHPublicNameDoesNotBypassExclusionsOrIPAdmission(t *testing.T) {
	for _, tc := range []struct {
		name, destination string
		exclude           []string
	}{
		{name: "unknown original IP", destination: "192.0.2.1:443"},
		{name: "excluded public name", destination: "secret.example:443", exclude: []string{"public.example"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := echPathGatewayConfig([]string{"secret.example"}, "reject")
			config.Interceptions[0].ExcludeDomains = tc.exclude
			m, _ := newTestManager(t, config, nil)
			address, workers := interceptListener(t, m, tc.destination, "127.0.0.1:1", "public.example")
			t.Cleanup(workers.Wait)
			raw, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", address)
			if err != nil {
				t.Fatal(err)
			}
			client := tls.Client(raw, &tls.Config{
				MinVersion:                     tls.VersionTLS13,
				ServerName:                     "secret.example",
				RootCAs:                        gatewayRootPool(t, m),
				EncryptedClientHelloConfigList: testECHConfigList(t, "public.example"),
			})
			defer client.Close()
			var rejection *tls.ECHRejectionError
			if err := client.HandshakeContext(t.Context()); err == nil || errors.As(err, &rejection) {
				t.Fatalf("unauthorized ECH handshake unexpectedly admitted: %v", err)
			}
			if got := m.CAStatus().CachedCertificates; got != 0 {
				t.Fatalf("signed certificates=%d for excluded or unknown ECH destination", got)
			}
		})
	}
}

func TestHTTPSMITMWithoutECHDoesNotAuthorizeMismatchedOuterSNI(t *testing.T) {
	config := echPathGatewayConfig([]string{"secret.example"}, "reject")
	m, _ := newTestManager(t, config, nil)
	address, workers := interceptListener(t, m, "secret.example:443", "127.0.0.1:1", "public.example")
	t.Cleanup(workers.Wait)
	raw, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	client := tls.Client(raw, &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: "public.example",
		RootCAs:    gatewayRootPool(t, m),
		NextProtos: []string{"http/1.1"},
	})
	defer client.Close()
	if err := client.HandshakeContext(t.Context()); err == nil {
		t.Fatal("TLS without ECH bypassed SNI allowlist")
	}
	if got := m.CAStatus().CachedCertificates; got != 0 {
		t.Fatalf("signed certificates=%d for unapproved non-ECH SNI", got)
	}
}

func echPathGatewayConfig(domains []string, unknownTLS string) contract.Config {
	return contract.Config{
		Gateways: []contract.Gateway{{
			ID:      "g",
			Name:    "g",
			Enabled: true,
			RuleIDs: []string{"block-ads"},
			Default: contract.Action{Type: "respond", Body: "allowed"},
		}},
		Rules: []contract.Rule{{
			ID:      "block-ads",
			Enabled: true,
			Match:   contract.Condition{Field: "path", Operator: "prefix", Value: "/ads/"},
			Action:  contract.Action{Type: "block", Status: http.StatusNoContent},
		}},
		Interceptions: []contract.Interception{{
			GatewayID:  "g",
			Mode:       "https_mitm",
			Domains:    domains,
			UnknownTLS: unknownTLS,
		}},
	}
}

func gatewayRootPool(t *testing.T, m *Manager) *x509.CertPool {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(m.CAStatus().CertificatePEM)) {
		t.Fatal("Gateway CA certificate unavailable")
	}
	return roots
}

func recordedGREASEECHClientHello(t *testing.T, serverName string, nextProtos []string) []byte {
	t.Helper()
	recorder := new(helloRecorder)
	client := newGREASEECHClient(t, recorder, serverName, nil, nextProtos)
	_ = client.HandshakeContext(t.Context())
	wire := recorder.Bytes()
	if len(wire) < 5 || wire[0] != 0x16 {
		t.Fatal("no ClientHello captured")
	}
	recordLength := int(binary.BigEndian.Uint16(wire[3:5])) + 5
	if recordLength > len(wire) {
		t.Fatalf("incomplete GREASE ClientHello record: got %d bytes, need %d", len(wire), recordLength)
	}
	return bytes.Clone(wire[:recordLength])
}

func testECHConfigList(t *testing.T, publicName string) []byte {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(publicName) == 0 || len(publicName) > 255 {
		t.Fatalf("invalid ECH public name %q", publicName)
	}

	contents := []byte{7}                     // config_id
	contents = appendUint16(contents, 0x0020) // DHKEM(X25519, HKDF-SHA256)
	contents = appendUint16(contents, uint16(len(key.PublicKey().Bytes())))
	contents = append(contents, key.PublicKey().Bytes()...)
	contents = appendUint16(contents, 4)      // cipher suite vector length
	contents = appendUint16(contents, 0x0001) // HKDF-SHA256
	contents = appendUint16(contents, 0x0001) // AES-128-GCM
	contents = append(contents, 32)           // maximum name length
	contents = append(contents, byte(len(publicName)))
	contents = append(contents, publicName...)
	contents = appendUint16(contents, 0) // no config extensions

	config := appendUint16(nil, encryptedClientHelloExtension)
	config = appendUint16(config, uint16(len(contents)))
	config = append(config, contents...)
	list := appendUint16(nil, uint16(len(config)))
	return append(list, config...)
}

func appendUint16(dst []byte, value uint16) []byte {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	return append(dst, encoded[:]...)
}

func newGREASEECHClient(t *testing.T, conn net.Conn, serverName string, roots *x509.CertPool, nextProtos []string) *utls.UConn {
	t.Helper()
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_133)
	if err != nil {
		t.Fatal(err)
	}
	foundALPN := false
	foundECHGrease := false
	for i := 0; i < len(spec.Extensions); i++ {
		extension := spec.Extensions[i]
		if _, ok := extension.(*utls.ALPNExtension); ok {
			foundALPN = true
			if nextProtos == nil {
				spec.Extensions = append(spec.Extensions[:i], spec.Extensions[i+1:]...)
				i--
				continue
			}
			spec.Extensions[i] = &utls.ALPNExtension{AlpnProtocols: nextProtos}
		}
		if _, ok := extension.(*utls.GREASEEncryptedClientHelloExtension); ok {
			foundECHGrease = true
		}
	}
	if !foundALPN {
		t.Fatal("Chrome ClientHello preset has no ALPN extension")
	}
	if !foundECHGrease {
		t.Fatal("Chrome ClientHello preset has no GREASE ECH extension")
	}
	client := utls.UClient(conn, &utls.Config{ServerName: serverName, RootCAs: roots}, utls.HelloCustom)
	if err := client.ApplyPreset(&spec); err != nil {
		t.Fatal(err)
	}
	return client
}
