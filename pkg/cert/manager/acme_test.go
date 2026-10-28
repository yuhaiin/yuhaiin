package manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store/certificates"
	"golang.org/x/crypto/acme"
)

// testCA verifies actual ES256 JWS requests and the CSR, then follows the real
// HTTP-01 handler before signing. No external ACME/DNS service is used.
type testCA struct {
	t          *testing.T
	mu         sync.Mutex
	server     *httptest.Server
	root       *x509.Certificate
	rootKey    *ecdsa.PrivateKey
	account    *ecdsa.PublicKey
	nonces     map[string]bool
	accounts   int
	valid      bool
	serial     int64
	chain      []byte
	badSAN     bool
	challenges *HTTPChallenges
	gateway    string
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Local ACME test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ca := &testCA{t: t, root: root, rootKey: key, nonces: map[string]bool{}, gateway: uuid.New().String(), serial: 1}
	ca.challenges = NewHTTPChallenges(func(id string) bool { return id == ca.gateway })
	ca.server = httptest.NewTLSServer(http.HandlerFunc(ca.serve))
	t.Cleanup(ca.server.Close)
	return ca
}

func (ca *testCA) config() contract.Config {
	return contract.Config{ID: uuid.New().String(), Name: "Local site", Domains: []string{"site.example"}, DirectoryURL: ca.server.URL + "/directory", Email: "ops@example.com", TermsAccepted: true, AutoRenew: true, Challenge: contract.Challenge{Type: "http-01", HTTPGatewayID: ca.gateway}, TrustPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.root.Raw}))}
}

func (ca *testCA) serve(w http.ResponseWriter, r *http.Request) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	nonce := uuid.New().String()
	ca.nonces[nonce] = true
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/directory" {
		ca.respond(w, map[string]any{"newNonce": ca.server.URL + "/nonce", "newAccount": ca.server.URL + "/account", "newOrder": ca.server.URL + "/new-order"})
		return
	}
	if r.URL.Path == "/nonce" && r.Method == http.MethodHead {
		return
	}
	payload, ok := ca.verifyJWS(r)
	if !ok {
		http.Error(w, "invalid JWS", 400)
		return
	}
	switch r.URL.Path {
	case "/account":
		ca.accounts++
		w.Header().Set("Location", ca.server.URL+"/account/1")
		w.WriteHeader(http.StatusCreated)
		ca.respond(w, map[string]any{"status": "valid"})
	case "/new-order":
		var request struct {
			Identifiers []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"identifiers"`
		}
		if err := json.Unmarshal(payload, &request); err != nil || len(request.Identifiers) != 1 || request.Identifiers[0].Value != "site.example" {
			ca.t.Error("unexpected order identifiers")
			http.Error(w, "identifiers", 400)
			return
		}
		ca.valid = false
		ca.chain = nil
		w.Header().Set("Location", ca.server.URL+"/order")
		w.WriteHeader(http.StatusCreated)
		ca.order(w)
	case "/authorization":
		status := "pending"
		if ca.valid {
			status = "valid"
		}
		ca.respond(w, map[string]any{"status": status, "identifier": map[string]string{"type": "dns", "value": "site.example"}, "challenges": []map[string]string{{"type": "http-01", "url": ca.server.URL + "/challenge", "token": strings.Repeat("t", 32), "status": status}}})
	case "/challenge":
		request := httptest.NewRequest(http.MethodGet, "http://site.example/.well-known/acme-challenge/"+strings.Repeat("t", 32), nil)
		recorder := httptest.NewRecorder()
		thumbprint, err := acme.JWKThumbprint(ca.account)
		if err != nil || !ca.challenges.Serve(ca.gateway, recorder, request) || recorder.Code != 200 || recorder.Body.String() != strings.Repeat("t", 32)+"."+thumbprint {
			ca.t.Error("HTTP-01 ownership proof failed")
			http.Error(w, "challenge", 400)
			return
		}
		ca.valid = true
		ca.respond(w, map[string]any{"type": "http-01", "status": "valid", "url": ca.server.URL + "/challenge", "token": strings.Repeat("t", 32)})
	case "/order":
		ca.order(w)
	case "/finalize":
		if !ca.valid {
			http.Error(w, "not authorized", http.StatusForbidden)
			return
		}
		var request struct {
			CSR string `json:"csr"`
		}
		if err := json.Unmarshal(payload, &request); err != nil {
			ca.t.Error(err)
			http.Error(w, "csr", 400)
			return
		}
		der, err := base64.RawURLEncoding.DecodeString(request.CSR)
		if err != nil {
			ca.t.Error(err)
			http.Error(w, "csr", 400)
			return
		}
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil || csr.CheckSignature() != nil {
			ca.t.Error("CSR signature invalid")
			http.Error(w, "csr", 400)
			return
		}
		if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "site.example" {
			ca.t.Error("CSR SAN mismatch")
			http.Error(w, "csr", 400)
			return
		}
		ca.serial++
		names := csr.DNSNames
		if ca.badSAN {
			names = []string{"other.example"}
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(ca.serial), DNSNames: names, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		issued, err := x509.CreateCertificate(rand.Reader, leaf, ca.root, csr.PublicKey, ca.rootKey)
		if err != nil {
			ca.t.Error(err)
			http.Error(w, "sign", 500)
			return
		}
		ca.chain = encodeChain([][]byte{issued, ca.root.Raw})
		w.Header().Set("Location", ca.server.URL+"/order")
		ca.order(w)
	case "/certificate":
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(ca.chain)
	default:
		http.NotFound(w, r)
	}
}

func (ca *testCA) order(w http.ResponseWriter) {
	status := "pending"
	if ca.valid {
		status = "ready"
	}
	if len(ca.chain) > 0 {
		status = "valid"
	}
	ca.respond(w, map[string]any{"status": status, "authorizations": []string{ca.server.URL + "/authorization"}, "finalize": ca.server.URL + "/finalize", "certificate": ca.server.URL + "/certificate"})
}

func (ca *testCA) respond(w http.ResponseWriter, value any) {
	if err := json.MarshalWrite(w, value); err != nil {
		ca.t.Error(err)
	}
}

func (ca *testCA) verifyJWS(r *http.Request) ([]byte, bool) {
	if r.Method != http.MethodPost {
		return nil, false
	}
	var envelope struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, false
	}
	if err = json.Unmarshal(data, &envelope); err != nil {
		return nil, false
	}
	protected, err := base64.RawURLEncoding.DecodeString(envelope.Protected)
	if err != nil {
		return nil, false
	}
	var header struct {
		Algorithm string `json:"alg"`
		Nonce     string `json:"nonce"`
		URL       string `json:"url"`
		KID       string `json:"kid"`
		JWK       *struct {
			KTY   string `json:"kty"`
			Curve string `json:"crv"`
			X     string `json:"x"`
			Y     string `json:"y"`
		} `json:"jwk"`
	}
	if err = json.Unmarshal(protected, &header); err != nil || header.Algorithm != "ES256" || header.URL != ca.server.URL+r.URL.Path || !ca.nonces[header.Nonce] {
		return nil, false
	}
	delete(ca.nonces, header.Nonce)
	public := ca.account
	if header.JWK != nil {
		if header.JWK.KTY != "EC" || header.JWK.Curve != "P-256" {
			return nil, false
		}
		x, err := base64.RawURLEncoding.DecodeString(header.JWK.X)
		if err != nil {
			return nil, false
		}
		y, err := base64.RawURLEncoding.DecodeString(header.JWK.Y)
		if err != nil {
			return nil, false
		}
		if len(x) != 32 || len(y) != 32 {
			return nil, false
		}
		public, err = ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return nil, false
		}
		if ca.account != nil && !ca.account.Equal(public) {
			return nil, false
		}
	} else if header.KID != ca.server.URL+"/account/1" {
		return nil, false
	}
	if public == nil {
		return nil, false
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != 64 {
		return nil, false
	}
	digest := sha256.Sum256([]byte(envelope.Protected + "." + envelope.Payload))
	if !ecdsa.Verify(public, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return nil, false
	}
	ca.account = public
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	return payload, err == nil
}

func TestLocalACMEHTTP01IssuanceRenewalAndTLSHotReplacement(t *testing.T) {
	ca := newTestCA(t)
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := certificates.New(db.DB())
	cfg := ca.config()
	resource, err := store.Save(t.Context(), cfg, 0)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &Issuer{Store: store, Client: ca.server.Client(), Presenter: HTTPPresenter{ca.challenges}}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	material, err := issuer.Issue(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := ValidateMaterial(cfg, material, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{verified.Leaf.NotBefore.Add(-time.Second), verified.Leaf.NotAfter.Add(time.Second)} {
		if _, err := ValidateMaterial(cfg, material, at); err == nil {
			t.Fatal("invalid certificate lifetime accepted")
		}
	}
	publish := func(material certificates.Material) {
		t.Helper()
		owner := uuid.New().String()
		now := time.Now()
		if ok, err := store.Acquire(ctx, cfg.ID, resource.Revision, owner, now, time.Minute); err != nil || !ok {
			t.Fatal(ok, err)
		}
		if err := store.Complete(ctx, cfg.ID, resource.Revision, owner, now, contract.Status{State: "ready"}, &material); err != nil {
			t.Fatal(err)
		}
	}
	publish(material)
	cache := NewCache(store)
	if err = cache.Reload(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	https := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	https.TLS = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: cache.GetCertificate([]string{cfg.ID})}
	https.StartTLS()
	defer https.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ca.root)
	dial := func(name string) (*tls.Conn, error) {
		return tls.Dial("tcp", https.Listener.Addr().String(), &tls.Config{RootCAs: roots, ServerName: name, MinVersion: tls.VersionTLS12})
	}
	old, err := dial("site.example")
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	oldSerial := old.ConnectionState().PeerCertificates[0].SerialNumber.String()
	renewed, err := issuer.Issue(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	publish(renewed)
	if err = cache.Reload(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	current, err := dial("site.example")
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	if current.ConnectionState().PeerCertificates[0].SerialNumber.String() == oldSerial {
		t.Fatal("new TLS connection retained old certificate")
	}
	if old.ConnectionState().PeerCertificates[0].SerialNumber.String() != oldSerial {
		t.Fatal("existing TLS connection changed identity")
	}
	if _, err = io.WriteString(old, "GET / HTTP/1.1\r\nHost: site.example\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal("old TLS stream interrupted", err)
	}
	response, err := io.ReadAll(old)
	if err != nil || !strings.Contains(string(response), "ok") {
		t.Fatal("old TLS stream unusable after renewal", err)
	}
	if bad, err := dial("wrong.example"); err == nil {
		_ = bad.Close()
		t.Fatal("incorrect SNI accepted")
	}
	ca.mu.Lock()
	ca.badSAN = true
	ca.mu.Unlock()
	if _, err = issuer.Issue(ctx, cfg); err == nil {
		t.Fatal("CA returned wrong SAN without rejection")
	}
	if _, err := db.DB().ExecContext(ctx, `UPDATE managed_certificate_material SET certificate_pem='malformed replacement' WHERE certificate_id=?`, cfg.ID); err != nil {
		t.Fatal(err)
	}
	if err := cache.Reload(ctx, time.Now()); err == nil {
		t.Fatal("malformed material was not reported")
	}
	ca.mu.Lock()
	accounts := ca.accounts
	ca.mu.Unlock()
	ca.challenges.mu.Lock()
	pending := len(ca.challenges.pending)
	ca.challenges.mu.Unlock()
	if accounts != 1 || pending != 0 {
		t.Fatalf("account reuse/cleanup: registrations=%d challenges=%d", accounts, pending)
	}
	// Failed issuance did not publish: the last valid certificate still works.
	stillValid, err := dial("site.example")
	if err != nil {
		t.Fatal(err)
	}
	_ = stillValid.Close()
}

func TestHTTP01HostIsolationAndCancellation(t *testing.T) {
	gateway := uuid.New().String()
	h := NewHTTPChallenges(func(id string) bool { return id == gateway })
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	token := strings.Repeat("t", 32)
	cleanup, err := h.Present(ctx, gateway, "site.example", token, token+".proof")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	for _, test := range []struct {
		gateway, host, path, method string
		code                        int
	}{
		{gateway, "site.example", "/.well-known/acme-challenge/" + token, "GET", 200},
		{gateway, "wrong.example", "/.well-known/acme-challenge/" + token, "GET", 404},
		{"other", "site.example", "/.well-known/acme-challenge/" + token, "GET", 404},
		{gateway, "site.example", "/.well-known/acme-challenge/" + token, "POST", 404},
		{gateway, "site.example", "/.well-known/acme-challenge/" + token + "?a=b", "GET", 404},
	} {
		r := httptest.NewRequest(test.method, "http://"+test.host+test.path, nil)
		w := httptest.NewRecorder()
		if !h.Serve(test.gateway, w, r) || w.Code != test.code {
			t.Fatalf("challenge isolation: %s %s got %d want %d", test.method, test.host, w.Code, test.code)
		}
	}
	cancel()
	cleanup()
	w := httptest.NewRecorder()
	h.Serve(gateway, w, httptest.NewRequest("GET", "http://site.example/.well-known/acme-challenge/"+token, nil))
	if w.Code != 404 {
		t.Fatal("cancelled challenge served")
	}
}

func TestACMEHTTPSVerificationAndOriginFence(t *testing.T) {
	ca := newTestCA(t)
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	issuer := Issuer{Store: certificates.New(db.DB()), Client: &http.Client{Transport: transport}, Presenter: HTTPPresenter{ca.challenges}}
	if _, err := issuer.Issue(ctx, ca.config()); err == nil {
		t.Fatal("untrusted HTTPS ACME endpoint accepted")
	}
	// A CA-provided URL must not escape the configured origin, including through
	// redirects. The destination must receive no request or account signature.
	var calls atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer other.Close()
	origin, _ := url.Parse(ca.server.URL)
	fence := originTransport{other.Client().Transport, origin}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, other.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response, err := fence.RoundTrip(request); err == nil {
		_ = response.Body.Close()
		t.Fatal("cross-origin ACME request accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("cross-origin endpoint received a request")
	}
}

func TestACMEResponseMemoryBound(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.(http.Flusher).Flush()
		_, _ = w.Write(make([]byte, 2<<20))
	}))
	defer server.Close()
	origin, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := originTransport{server.Client().Transport, origin}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err == nil || len(data) > 1<<20 {
		t.Fatal("unbounded ACME response", len(data), err)
	}
}
