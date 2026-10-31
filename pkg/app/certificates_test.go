package app

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/cert"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type certificateTestProxy struct {
	netapi.Proxy
	address string
	dials   atomic.Int32
}

func (p *certificateTestProxy) Conn(ctx context.Context, a netapi.Address) (net.Conn, error) {
	p.dials.Add(1)
	if a.Hostname() != "ca.example" {
		return nil, errors.New("unexpected governed destination")
	}
	return new(net.Dialer).DialContext(ctx, "tcp", p.address)
}

func TestCertificateHTTPSUsesGovernedProxyAndScopedTrust(t *testing.T) {
	ca, err := cert.GenerateCa()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.GenerateServerCert("ca.example")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := leaf.TlsCert()
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); _, _ = io.WriteString(w, "verified") }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	server.StartTLS()
	defer server.Close()
	proxy := &certificateTestProxy{address: server.Listener.Addr().String()}
	root, err := ca.CertBytes()
	if err != nil {
		t.Fatal(err)
	}
	client, transport, err := certificateClient(func(context.Context) (netapi.Proxy, error) { return proxy, nil }, string(root))
	if err != nil {
		t.Fatal(err)
	}
	defer transport.CloseIdleConnections()
	response, err := client.Get("https://ca.example/directory")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if proxy.dials.Load() != 1 || requests.Load() != 1 {
		t.Fatal("request bypassed governed transport")
	}
	separate, other, err := certificateClient(func(context.Context) (netapi.Proxy, error) { return proxy, nil }, "")
	if err != nil {
		t.Fatal(err)
	}
	defer other.CloseIdleConnections()
	if response, err := separate.Get("https://ca.example/directory"); err == nil {
		_ = response.Body.Close()
		t.Fatal("CA-specific trust leaked into another client")
	}
	denied, blocked, err := certificateClient(func(context.Context) (netapi.Proxy, error) { return nil, errors.New("policy denied") }, string(root))
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.CloseIdleConnections()
	if response, err := denied.Get("https://ca.example/directory"); err == nil {
		_ = response.Body.Close()
		t.Fatal("policy failure used a fallback dialer")
	} else if !strings.Contains(err.Error(), "policy denied") {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatal("untrusted/denied client reached HTTPS handler")
	}
}
