package cloudflare

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/Asutorufa/yuhaiin/pkg/cert/manager/dnschallenge"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
	"github.com/Asutorufa/yuhaiin/pkg/store/certificates"
)

func providerFixture() (contract.DNSProvider, certificates.Secret, certificates.DNSCleanup) {
	p := contract.DNSProvider{ID: uuid.New().String(), Name: "Example zone", Type: "cloudflare", ZoneID: strings.Repeat("a", 32), ZoneName: "example.com"}
	r := certificates.DNSCleanup{ID: uuid.New().String(), ProviderID: p.ID, Name: "_acme-challenge.site.example.com", Value: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
	return p, certificates.NewSecret([]byte("private-test-token")), r
}

func TestCloudflareCreateAndOwnedCleanup(t *testing.T) {
	p, token, r := providerFixture()
	var mu sync.Mutex
	var created record
	var deleted []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if request.Header.Get("Authorization") != "Bearer "+string(token.Bytes()) {
			t.Error("missing scoped token")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		base := "/zones/" + p.ZoneID + "/dns_records"
		respond := func(result any) {
			if err := json.MarshalWrite(w, map[string]any{"success": true, "result": result}); err != nil {
				t.Error(err)
			}
		}
		switch request.Method {
		case http.MethodPost:
			if request.URL.Path != base {
				t.Error("wrong create path")
			}
			if err := json.UnmarshalRead(request.Body, &created); err != nil {
				t.Error(err)
			}
			if created.Type != "TXT" || created.Name != r.Name || created.Content != "\""+r.Value+"\"" || created.Comment != tag(r) || created.TTL != 60 {
				t.Error("incorrect TXT challenge")
			}
			created.ID = strings.Repeat("b", 32)
			respond(created)
		case http.MethodGet:
			if request.URL.Path == base { // Ignore filters deliberately: client must still filter ownership.
				if request.URL.Query().Get("comment.exact") != tag(r) || request.URL.Query().Get("name.exact") != r.Name {
					t.Error("missing narrow recovery filters")
				}
				foreign := created
				foreign.ID = strings.Repeat("c", 32)
				foreign.Comment = "another-owner"
				changed := created
				changed.ID = strings.Repeat("d", 32)
				changed.Content = "other-challenge"
				respond([]record{foreign, changed, created})
			} else {
				respond(created)
			}
		case http.MethodDelete:
			deleted = append(deleted, strings.TrimPrefix(request.URL.Path, base+"/"))
			respond(map[string]string{"id": created.ID})
		}
	}))
	defer server.Close()
	provider, err := newWithBase(server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	id, err := provider.Create(t.Context(), p, token, r)
	if err != nil || id != strings.Repeat("b", 32) {
		t.Fatal(id, err)
	}
	r.RecordID = id
	if err := provider.Cleanup(t.Context(), p, token, r); err != nil {
		t.Fatal(err)
	}
	r.RecordID = "" // Lost POST response: reconcile by exact random ownership tag.
	if err := provider.Cleanup(t.Context(), p, token, r); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(deleted) != 2 || deleted[0] != id || deleted[1] != id {
		t.Fatal("cleanup deleted foreign records", deleted)
	}
}

func TestCloudflareChangedOwnershipAndSanitizedFailure(t *testing.T) {
	p, token, r := providerFixture()
	r.RecordID = strings.Repeat("b", 32)
	var mu sync.Mutex
	mode := "changed"
	deletes := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if request.Method == http.MethodDelete {
			deletes++
			return
		}
		switch mode {
		case "changed":
			_ = json.MarshalWrite(w, map[string]any{"success": true, "result": record{ID: r.RecordID, Name: r.Name, Type: "TXT", Content: r.Value, Comment: "other owner"}})
		case "rate":
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write(token.Bytes())
		case "redirect":
			http.Redirect(w, request, "https://evil.example/secret", http.StatusTemporaryRedirect)
		case "large":
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			_, _ = w.Write(make([]byte, 2<<20))
		case "reject":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write(token.Bytes())
		}
	}))
	defer server.Close()
	provider, err := newWithBase(server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, next := range []string{"changed", "rate", "redirect", "large", "reject"} {
		mu.Lock()
		mode = next
		mu.Unlock()
		err := provider.Cleanup(t.Context(), p, token, r)
		if err == nil || strings.Contains(err.Error(), string(token.Bytes())) {
			t.Fatal("failure or credential leaked", err)
		}
		if next == "rate" {
			limited, ok := errors.AsType[*dnschallenge.Error](err)
			if !ok || limited.RetryAfter != 2*time.Minute {
				t.Fatal("retry-after lost", err)
			}
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if deletes != 0 {
		t.Fatal("changed ownership was deleted")
	}
}

func TestCloudflareRejectsUnverifiedTLSAndCancellation(t *testing.T) {
	p, token, r := providerFixture()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	provider, err := newWithBase(&http.Client{Transport: transport}, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Create(t.Context(), p, token, r); err == nil {
		t.Fatal("untrusted provider HTTPS accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := provider.Create(ctx, p, token, r); err == nil {
		t.Fatal("canceled create succeeded")
	}
}
