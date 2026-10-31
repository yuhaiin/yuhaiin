package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/Asutorufa/yuhaiin/pkg/cert"
	certmanager "github.com/Asutorufa/yuhaiin/pkg/cert/manager"
	certificate "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
	"github.com/Asutorufa/yuhaiin/pkg/store/certificates"
)

func TestManagedGatewayCertificateHotUpdateAndReferenceProtection(t *testing.T) {
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	resources := certificates.New(db.DB())
	ca, err := cert.GenerateCa()
	if err != nil {
		t.Fatal(err)
	}
	root, err := ca.CertBytes()
	if err != nil {
		t.Fatal(err)
	}
	cfg := certificate.Config{ID: uuid.New().String(), Name: "Site", Domains: []string{"site.example"}, DirectoryURL: certificate.LetsEncryptStaging, Email: "ops@example.com", TermsAccepted: true, AutoRenew: true, TrustPEM: string(root), Challenge: certificate.Challenge{Type: "http-01", HTTPGatewayID: uuid.New().String()}}
	r, err := resources.Save(t.Context(), cfg, 0)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := certmanager.New(certmanager.Options{Store: resources, Issue: func(context.Context, certificate.Config) (certificates.Material, error) {
		return certificates.Material{}, errors.New("not scheduled")
	}})
	if err != nil {
		t.Fatal(err)
	}
	publish := func() {
		t.Helper()
		leaf, err := ca.GenerateServerCert("site.example")
		if err != nil {
			t.Fatal(err)
		}
		chain, err := leaf.CertBytes()
		if err != nil {
			t.Fatal(err)
		}
		key, err := leaf.PrivateKeyBytes()
		if err != nil {
			t.Fatal(err)
		}
		material := certificates.Material{CertificatePEM: chain, PrivateKey: certificates.NewSecret(key)}
		if _, err := certmanager.ValidateMaterial(cfg, material, time.Now()); err != nil {
			t.Fatal(err)
		}
		owner := uuid.New().String()
		now := time.Now()
		if ok, err := resources.Acquire(t.Context(), cfg.ID, r.Revision, owner, now, time.Minute); err != nil || !ok {
			t.Fatal(ok, err)
		}
		if err := resources.Complete(t.Context(), cfg.ID, r.Revision, owner, now, certificate.Status{State: "ready"}, &material); err != nil {
			t.Fatal(err)
		}
		if err := controller.Cache.Reload(t.Context(), now); err != nil {
			t.Fatal(err)
		}
	}
	publish()
	m, err := NewManager(t.Context(), store.NewGatewayStore(db.DB()), nil, nil, WithManagedCertificates(controller.TLSConfig))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	gateway := contract.Gateway{ID: uuid.New().String(), Name: "Site listener", Enabled: true, Listen: "127.0.0.1:0", TLSMode: "termination", ManagedCertificateIDs: []string{cfg.ID}, Default: contract.Action{Type: "respond", Status: 200, Body: "still usable"}}
	saved, err := m.Save(t.Context(), contract.Config{Gateways: []contract.Gateway{gateway}})
	if err != nil {
		t.Fatal(err)
	}
	if err := resources.Delete(t.Context(), cfg.ID, r.Revision); !errors.Is(err, certificates.ErrInUse) {
		t.Fatal("active Gateway certificate deleted", err)
	}
	refs, err := resources.References(t.Context(), cfg.ID)
	if err != nil || len(refs) != 1 || refs[0].ID != gateway.ID {
		t.Fatal(refs, err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().ExecContext(t.Context(), `DELETE FROM certificate_references WHERE kind='gateway'`); err != nil {
		t.Fatal(err)
	}
	m, err = NewManager(t.Context(), store.NewGatewayStore(db.DB()), nil, nil, WithManagedCertificates(controller.TLSConfig))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := resources.Delete(t.Context(), cfg.ID, r.Revision); !errors.Is(err, certificates.ErrInUse) {
		t.Fatal("restart did not repair imported certificate references", err)
	}
	address := m.listeners[gateway.Listen].raw.Addr().String()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(root)
	dial := func(name string) (*tls.Conn, error) {
		return tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", address, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: name})
	}
	old, err := dial("site.example")
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	serial := old.ConnectionState().PeerCertificates[0].SerialNumber.String()
	publish()
	current, err := dial("site.example")
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	if current.ConnectionState().PeerCertificates[0].SerialNumber.String() == serial || m.Config().Revision != saved.Revision {
		t.Fatal("certificate publication rebuilt Gateway configuration or retained old pair")
	}
	_ = old.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(old, "GET / HTTP/1.1\r\nHost: site.example\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(old)
	if err != nil || !strings.Contains(string(response), "still usable") {
		t.Fatal("existing TLS stream interrupted", err)
	}
	if bad, err := dial("other.example"); err == nil {
		_ = bad.Close()
		t.Fatal("wrong SNI accepted")
	}
	copy := m.Config()
	copy.Gateways = nil
	if _, err := m.Save(t.Context(), copy); err != nil {
		t.Fatal(err)
	}
	if err := resources.Delete(t.Context(), cfg.ID, r.Revision); err != nil {
		t.Fatal("removed Gateway left a stale certificate reference", err)
	}
}

func TestHTTP01UsesExplicitExistingPort80AndSourceACL(t *testing.T) {
	// This is the only test that needs the actual standard challenge port. All
	// protocol/provider tests use independent ephemeral local listeners.
	probe, err := net.Listen("tcp", "127.0.0.1:80")
	if err != nil {
		t.Skipf("local port 80 is unavailable: %v", err)
	}
	_ = probe.Close()
	var m *Manager
	challenges := certmanager.NewHTTPChallenges(func(id string) bool { return m != nil && m.HTTP01Available(id) })
	m, err = NewManager(t.Context(), &memoryStore{}, nil, nil, WithACMEHTTP01(challenges.Serve))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	id := uuid.New().String()
	cfg := contract.Config{Gateways: []contract.Gateway{{ID: id, Name: "Challenge", Enabled: true, Listen: "127.0.0.1:80", TLSMode: "off", ACMEHTTP01: true, Default: contract.Action{Type: "respond", Body: "ordinary"}}}}
	if _, err := m.Save(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	if !m.HTTP01Available(id) {
		t.Fatal("published challenge listener is unavailable")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	token := strings.Repeat("t", 32)
	cleanup, err := challenges.Present(ctx, id, "site.example", token, token+".proof")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	get := func(host string) int {
		t.Helper()
		request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://127.0.0.1:80/.well-known/acme-challenge/"+token, nil)
		request.Host = host
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		return response.StatusCode
	}
	if get("site.example") != http.StatusOK || get("other.example") != http.StatusNotFound {
		t.Fatal("Host proof isolation failed")
	}
	draft := m.Config()
	draft.Gateways[0].AllowedSources = []string{"192.0.2.0/24"}
	if _, err := m.Save(t.Context(), draft); err != nil {
		t.Fatal(err)
	}
	if get("site.example") != http.StatusForbidden {
		t.Fatal("HTTP-01 bypassed source ACL")
	}
	draft = m.Config()
	draft.Gateways[0].Listen = "127.0.0.1:8080"
	if _, err := m.Save(t.Context(), draft); err == nil {
		t.Fatal("HTTP-01 accepted an implicit nonstandard listener")
	}
}
