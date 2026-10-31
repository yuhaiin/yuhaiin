package manager

import (
	"context"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/Asutorufa/yuhaiin/pkg/cert/manager/dnschallenge"
	"github.com/Asutorufa/yuhaiin/pkg/cert/manager/dnschallenge/cloudflare"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
	"github.com/Asutorufa/yuhaiin/pkg/store/certificates"
)

// Only the test transport rewrites the fixed Cloudflare origin to a local TLS
// server. The production provider has no configurable origin or trust override.
type localCloudflareTransport struct {
	base   http.RoundTripper
	target *url.URL
}

func (t localCloudflareTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.URL = r.URL.Clone()
	r.URL.Scheme = t.target.Scheme
	r.URL.Host = t.target.Host
	return t.base.RoundTrip(r)
}

func TestLocalACMEDNS01WithCloudflareProvider(t *testing.T) {
	ca := newTestCA(t)
	store := managerStore(t)
	providerConfig, err := store.SaveProvider(t.Context(), contract.DNSProvider{ID: uuid.New().String(), Name: "Local DNS", Type: "cloudflare", ZoneID: strings.Repeat("a", 32), ZoneName: "site.example"}, certificates.NewSecret([]byte("local-provider-token")))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var record map[string]any
	creates, deletes := 0, 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer local-provider-token" {
			t.Error("missing DNS API authentication")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/client/v4/zones/"+providerConfig.ZoneID+"/dns_records") {
			t.Error("unexpected DNS API path")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.Method {
		case http.MethodPost:
			creates++
			if err := json.UnmarshalRead(r.Body, &record); err != nil {
				t.Error(err)
			}
			record["id"] = strings.Repeat("b", 32)
		case http.MethodDelete:
			deletes++
			defer func() { record = nil }()
		}
		if err := json.MarshalWrite(w, map[string]any{"success": true, "result": record}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	endpoint, _ := url.Parse(server.URL)
	provider, err := cloudflare.New(&http.Client{Transport: localCloudflareTransport{server.Client().Transport, endpoint}})
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(_ context.Context, name string) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		if record == nil || record["name"] != name {
			return nil, nil
		}
		value, _ := record["content"].(string)
		return []string{strings.Trim(value, "\"")}, nil
	}
	dns, err := dnschallenge.New(store, map[string]dnschallenge.Provider{"cloudflare": provider}, dnschallenge.Options{LookupTXT: lookup})
	if err != nil {
		t.Fatal(err)
	}
	ca.mu.Lock()
	ca.dnsProof = func(name, value string) bool {
		values, _ := lookup(t.Context(), name)
		return len(values) == 1 && values[0] == value
	}
	ca.mu.Unlock()
	cfg := ca.config()
	cfg.Challenge = contract.Challenge{Type: "dns-01", DNSProviderID: providerConfig.ID}
	issuer := Issuer{Store: store, Client: ca.server.Client(), Presenter: Presenters{DNS: dns}}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	material, err := issuer.Issue(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateMaterial(cfg, material, time.Now()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if creates != 1 || deletes != 1 || record != nil {
		t.Fatal("DNS issuance did not clean exact owned record", creates, deletes)
	}
	pending, err := store.PendingDNSCleanup(t.Context(), time.Now().Add(time.Hour))
	if err != nil || len(pending) != 0 {
		t.Fatal("DNS receipt retained after successful cleanup", pending, err)
	}
}
