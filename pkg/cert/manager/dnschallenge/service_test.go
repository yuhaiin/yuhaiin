package dnschallenge

import (
	"context"
	"encoding/base64"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"uuid"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store/certificates"
)

type testProvider struct {
	receipt                 certificates.DNSCleanup
	creates, cleanups       int
	failCreate, failCleanup bool
}

func (p *testProvider) Create(_ context.Context, _ contract.DNSProvider, _ certificates.Secret, r certificates.DNSCleanup) (string, error) {
	p.creates++
	p.receipt = r
	if p.failCreate {
		return "", errors.New("lost response")
	}
	return strings.Repeat("b", 32), nil
}
func (p *testProvider) Cleanup(context.Context, contract.DNSProvider, certificates.Secret, certificates.DNSCleanup) error {
	p.cleanups++
	if p.failCleanup {
		return errors.New("cleanup connection failed")
	}
	return nil
}

func TestDNSReceiptRecoveryAndPropagation(t *testing.T) {
	for _, scenario := range []string{"success", "lost_create", "cleanup_retry", "propagation_cancel"} {
		t.Run(scenario, func(t *testing.T) {
			db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			store := certificates.New(db.DB())
			p, err := store.SaveProvider(t.Context(), contract.DNSProvider{ID: uuid.New().String(), Name: "zone", Type: "cloudflare", ZoneID: strings.Repeat("a", 32), ZoneName: "example.com"}, certificates.NewSecret([]byte("test-token")))
			if err != nil {
				t.Fatal(err)
			}
			provider := &testProvider{failCreate: scenario == "lost_create", failCleanup: scenario == "cleanup_retry"}
			now := time.Now()
			value := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
			lookups := 0
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			service, err := New(store, map[string]Provider{"cloudflare": provider}, Options{Now: func() time.Time { return now }, LookupTXT: func(ctx context.Context, name string) ([]string, error) {
				lookups++
				if name != "_acme-challenge.site.example.com" {
					t.Fatal(name)
				}
				if scenario == "propagation_cancel" {
					return nil, errors.New("not propagated")
				}
				return []string{"foreign", value}, nil
			}, Wait: func(context.Context, time.Duration) error { return context.Canceled }})
			if err != nil {
				t.Fatal(err)
			}
			cleanup, err := service.Present(ctx, p.ID, "site.example.com", value)
			if scenario == "lost_create" || scenario == "propagation_cancel" {
				if err == nil {
					t.Fatal("failed challenge succeeded")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				cancel()
				cleanup()
				cleanup()
			}
			if provider.creates != 1 {
				t.Fatal("create was replayed", provider.creates)
			}
			if scenario != "lost_create" && lookups == 0 {
				t.Fatal("provider success substituted for actual DNS evidence")
			}
			now = now.Add(5 * time.Minute)
			pending, err := store.PendingDNSCleanup(t.Context(), now)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "lost_create" || scenario == "cleanup_retry" {
				if len(pending) != 1 {
					t.Fatal("uncertain cleanup receipt lost", pending)
				}
				if err := store.DeleteProvider(t.Context(), p.ID, p.Revision); !errors.Is(err, certificates.ErrInUse) {
					t.Fatal("provider deleted with pending records", err)
				}
				provider.failCleanup = false
				restarted, err := New(store, map[string]Provider{"cloudflare": provider}, service.options)
				if err != nil {
					t.Fatal(err)
				}
				if err := restarted.Reconcile(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			pending, err = store.PendingDNSCleanup(t.Context(), now)
			if err != nil || len(pending) != 0 {
				t.Fatal("cleanup did not finish", pending, err)
			}
			if _, err := service.Present(ctx, p.ID, "other-zone.net", value); err == nil {
				t.Fatal("out-of-zone challenge accepted")
			}
		})
	}
}
