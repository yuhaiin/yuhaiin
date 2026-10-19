package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type helloRecorder struct{ bytes.Buffer }

func (*helloRecorder) Read([]byte) (int, error)         { return 0, io.EOF }
func (*helloRecorder) Close() error                     { return nil }
func (*helloRecorder) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*helloRecorder) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*helloRecorder) SetDeadline(time.Time) error      { return nil }
func (*helloRecorder) SetReadDeadline(time.Time) error  { return nil }
func (*helloRecorder) SetWriteDeadline(time.Time) error { return nil }

func TestUnsupportedTLSAdmissionIsLosslessBeforeHandshake(t *testing.T) {
	for _, protocol := range []string{"", "custom-protocol"} {
		for _, ech := range []bool{false, true} {
			for _, strategy := range []string{"passthrough", "reject"} {
				name := protocol + "/" + strategy
				if ech {
					name += "/ech-grease"
				}
				t.Run(name, func(t *testing.T) {
					config := contract.Config{Gateways: []contract.Gateway{{ID: "g", Name: "g", Enabled: true, Default: contract.Action{Type: "forward"}}}, Interceptions: []contract.Interception{{GatewayID: "g", Mode: "https_mitm", Domains: []string{"example.com"}, UnknownTLS: strategy}}}
					m, _ := newTestManager(t, config, nil)
					var hello []byte
					if ech {
						var nextProtos []string
						if protocol != "" {
							nextProtos = []string{protocol}
						}
						hello = recordedGREASEECHClientHello(t, "example.com", nextProtos)
					} else {
						recorded := new(helloRecorder)
						clientConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "example.com"}
						if protocol != "" {
							clientConfig.NextProtos = []string{protocol}
						}
						client := tls.Client(recorded, clientConfig)
						_ = client.HandshakeContext(t.Context())
						hello = bytes.Clone(recorded.Bytes())
						if len(hello) == 0 {
							t.Fatal("no ClientHello")
						}
					}
					left, right := net.Pipe()
					defer left.Close()
					defer right.Close()
					go func() { _, _ = right.Write(hello) }()
					dst, _ := netapi.ParseAddress("tcp", "example.com:443")
					ctx := netapi.WithContext(t.Context()).SetInboundID("in")
					meta := &netapi.StreamMeta{Src: left, Address: dst}
					handled := m.InterceptGateway(ctx, meta, "g")
					if handled != (strategy == "reject") {
						t.Fatalf("handled=%t", handled)
					}
					if got := m.current.Load().gateways["g"].engine.Counters.ProtocolFailures.Load(); got != 1 {
						t.Fatalf("protocol failures=%d, want 1 for unsupported ALPN", got)
					}
					if !handled {
						replay := make([]byte, len(hello))
						if _, err := io.ReadFull(meta.Src, replay); err != nil || !bytes.Equal(replay, hello) {
							t.Fatalf("ClientHello changed: %v", err)
						}
						// Probe parser alerts must not reach the client, even on protocol rejection.
						_ = right.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
						var b [1]byte
						if n, err := right.Read(b[:]); n != 0 || err == nil {
							t.Fatalf("probe wrote TLS data: n=%d err=%v", n, err)
						}
					}
				})
			}
		}
	}
}

func TestMITMWithoutSNIUsesIPDestinationSAN(t *testing.T) {
	config := contract.Config{Gateways: []contract.Gateway{{ID: "g", Name: "g", Enabled: true, Default: contract.Action{Type: "respond", Body: "ip endpoint"}}}, Interceptions: []contract.Interception{{GatewayID: "g", Mode: "https_mitm", Domains: []string{"127.0.0.1"}}}}
	m, _ := newTestManager(t, config, nil)
	address, _ := interceptListener(t, m, "127.0.0.1:443", "127.0.0.1:1")
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(m.CAStatus().CertificatePEM))
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "127.0.0.1", NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.ConnectionState().PeerCertificates[0].VerifyHostname("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(conn)
	if err != nil || !bytes.Contains(data, []byte("ip endpoint")) {
		t.Fatalf("response=%s err=%v", data, err)
	}
}

func TestMITMDoesNotFallbackAfterUpstreamRequiresClientCertificate(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("upstream accepted missing client certificate") }))
	upstream.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAnyClientCert}
	upstream.StartTLS()
	defer upstream.Close()
	trust := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})
	p := &mockOutbound{destination: strings.TrimPrefix(upstream.URL, "https://")}
	config := contract.Config{Gateways: []contract.Gateway{{ID: "g", Name: "g", Enabled: true, Default: contract.Action{Type: "reverse_proxy", Upstream: "u"}}}, Upstreams: []contract.Upstream{{ID: "u", Backends: []contract.Backend{{URL: upstream.URL}}, TrustPEM: string(trust)}}, Interceptions: []contract.Interception{{GatewayID: "g", Mode: "https_mitm", Domains: []string{"example.com"}}}}
	m, _ := newTestManager(t, config, func(_ context.Context, a netapi.Address, _ route.Target) (Selection, error) {
		return Selection{Proxy: p, Identity: "up", Destination: a}, nil
	})
	address, _ := interceptListener(t, m, "example.com:443", p.destination)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(m.CAStatus().CertificatePEM))
	transport := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return new(net.Dialer).DialContext(ctx, "tcp", address)
	}}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: 2 * time.Second}).Get("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadGateway || p.dials.Load() != 1 {
		t.Fatalf("status=%d dials=%d", response.StatusCode, p.dials.Load())
	}
}

func TestUnselectedInboundDoesNotProbe(t *testing.T) {
	config := contract.Config{Gateways: []contract.Gateway{{ID: "g", Name: "g", Enabled: true, Default: contract.Action{Type: "forward"}}}, Interceptions: []contract.Interception{{GatewayID: "g", Mode: "http_only"}}}
	m, _ := newTestManager(t, config, nil)
	c := &failOnReadConn{}
	dst, _ := netapi.ParseAddress("tcp", "example.com:80")
	meta := &netapi.StreamMeta{Src: c, Address: dst}
	if m.InterceptGateway(netapi.WithContext(t.Context()).SetInboundID("other"), meta, "other") || c.read {
		t.Fatal("unselected inbound was probed")
	}
}

type failOnReadConn struct {
	helloRecorder
	read bool
}

func (c *failOnReadConn) Read([]byte) (int, error) {
	c.read = true
	return 0, errors.New("unexpected read")
}

// A short test deadline exercises the production probe timeout and replay path
// without spending ten seconds waiting for an intentionally incomplete hello.
type shortProbeConn struct{ net.Conn }

func (c shortProbeConn) SetReadDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		deadline = time.Now().Add(10 * time.Millisecond)
	}
	return c.Conn.SetReadDeadline(deadline)
}
func TestTLSProbeTimeoutLeavesAllBytesForPassthrough(t *testing.T) {
	config := contract.Config{Gateways: []contract.Gateway{{ID: "g", Name: "g", Enabled: true, Default: contract.Action{Type: "forward"}}}, Interceptions: []contract.Interception{{GatewayID: "g", Mode: "https_mitm", Domains: []string{"example.com"}}}}
	m, _ := newTestManager(t, config, nil)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	go func() { _, _ = right.Write([]byte{0x16}) }()
	dst, _ := netapi.ParseAddress("tcp", "example.com:443")
	meta := &netapi.StreamMeta{Src: shortProbeConn{left}, Address: dst}
	if m.InterceptGateway(netapi.WithContext(t.Context()).SetInboundID("in"), meta, "g") {
		t.Fatal("incomplete hello intercepted")
	}
	var b [1]byte
	if _, err := io.ReadFull(meta.Src, b[:]); err != nil || b[0] != 0x16 {
		t.Fatalf("probe lost prefix: %x %v", b, err)
	}
}
