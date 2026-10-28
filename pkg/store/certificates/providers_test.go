package certificates

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"
	"uuid"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestProviderSecretsReferencesAndZoneBoundaries(t *testing.T) {
	s, db, c := fixture(t)
	p := contract.DNSProvider{ID: uuid.New().String(), Name: "Zone", Type: "cloudflare", ZoneID: strings.Repeat("a", 32), ZoneName: "example.com"}
	private := NewSecret([]byte("private-provider-token-marker"))
	p, err := s.SaveProvider(t.Context(), p, private)
	if err != nil {
		t.Fatal(err)
	}
	p.Name = "Renamed"
	p, err = s.SaveProvider(t.Context(), p, Secret{})
	if err != nil {
		t.Fatal(err)
	}
	projection, token, err := s.Provider(t.Context(), p.ID)
	if err != nil || !projection.HasCredential || !bytes.Equal(token.Bytes(), private.Bytes()) {
		t.Fatal("token lost on edit", projection, err)
	}
	data, err := json.Marshal(projection)
	if err != nil || bytes.Contains(data, private.Bytes()) {
		t.Fatal("provider read exposed token", err)
	}
	c.Challenge = contract.Challenge{Type: "dns-01", DNSProviderID: p.ID}
	c.Domains = []string{"*.example.com", "example.com"}
	r, err := s.Save(t.Context(), c, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteProvider(t.Context(), p.ID, p.Revision); !errors.Is(err, ErrInUse) {
		t.Fatal("referenced provider deleted", err)
	}
	changed := p
	changed.ZoneName = "other.example"
	if _, err := s.SaveProvider(t.Context(), changed, Secret{}); !errors.Is(err, ErrInUse) {
		t.Fatal("referenced zone rebound", err)
	}
	c.ID = uuid.New().String()
	c.Domains = []string{"evilexample.com"}
	if _, err := s.Save(t.Context(), c, 0); err == nil {
		t.Fatal("suffix-confused zone accepted")
	}
	export, err := sqlite.ExportConfig(t.Context(), db.DB())
	if err != nil || bytes.Contains(export, private.Bytes()) {
		t.Fatal("provider token in ordinary export", err)
	}
	if err := s.Delete(t.Context(), r.Config.ID, r.Revision); err != nil {
		t.Fatal(err)
	}
	receipt := DNSCleanup{ID: uuid.New().String(), ProviderID: p.ID, Name: "_acme-challenge.example.com", Value: strings.Repeat("a", 43), NotBefore: time.Now().Add(time.Hour).UnixMilli()}
	if err := s.AddDNSCleanup(t.Context(), receipt, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteProvider(t.Context(), p.ID, p.Revision); !errors.Is(err, ErrInUse) {
		t.Fatal("pending-cleanup provider deleted", err)
	}
	if err := s.FinishDNSCleanup(t.Context(), receipt.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteProvider(t.Context(), p.ID, p.Revision); err != nil {
		t.Fatal(err)
	}
}

func TestManualQueueCannotBypassPersistentFailureBackoff(t *testing.T) {
	s, _, c := fixture(t)
	r, err := s.Save(t.Context(), c, 0)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	owner := uuid.New().String()
	if ok, err := s.Acquire(t.Context(), c.ID, r.Revision, owner, now, time.Minute); err != nil || !ok {
		t.Fatal(ok, err)
	}
	status := contract.Status{State: "failed", Failures: 1, LastAttempt: now, NextAttempt: now.Add(24 * time.Hour), FailureCode: "ca_rate_limited"}
	if err := s.Complete(t.Context(), c.ID, r.Revision, owner, now, status, nil); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		queued, err := s.Queue(t.Context(), c.ID, r.Revision, now.Add(time.Minute))
		if err != nil || !queued.Status.NextAttempt.Equal(status.NextAttempt) {
			t.Fatal("manual request defeated backoff", queued.Status, err)
		}
	}
	c.Name = "Edited during backoff"
	updated, err := s.Save(t.Context(), c, r.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status.NextAttempt.Before(status.NextAttempt) {
		t.Fatal("configuration edit defeated backoff")
	}
}
