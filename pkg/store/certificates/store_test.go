package certificates

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func fixture(t *testing.T) (*Store, *sqlite.Store, contract.Config) {
	t.Helper()
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	c := contract.Config{ID: uuid.New().String(), Name: "Site", Domains: []string{"site.example"}, DirectoryURL: contract.LetsEncryptStaging, Email: "ops@example.com", TermsAccepted: true, AutoRenew: true, Challenge: contract.Challenge{Type: "http-01", HTTPGatewayID: uuid.New().String()}}
	return New(db.DB()), db, c
}

func TestLeaseRevisionAndFailureRetainOldMaterial(t *testing.T) {
	s, _, c := fixture(t)
	r, err := s.Save(t.Context(), c, 0)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	var winners atomic.Int32
	var owner string
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			candidate := uuid.New().String()
			ok, err := s.Acquire(t.Context(), c.ID, r.Revision, candidate, now, time.Minute)
			if err != nil {
				t.Error(err)
			}
			if ok {
				winners.Add(1)
				mu.Lock()
				owner = candidate
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("lease winners=%d", winners.Load())
	}
	m := Material{CertificatePEM: []byte("certificate-one"), PrivateKey: NewSecret([]byte("secret-one"))}
	if err := s.Complete(t.Context(), c.ID, r.Revision, uuid.New().String(), now, contract.Status{State: "ready"}, &m); !errors.Is(err, ErrConflict) {
		t.Fatal("foreign job published", err)
	}
	if err := s.Complete(t.Context(), c.ID, r.Revision, owner, now, contract.Status{State: "ready"}, &m); err != nil {
		t.Fatal(err)
	}
	owner = uuid.New().String()
	ok, err := s.Acquire(t.Context(), c.ID, r.Revision, owner, now, time.Minute)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	if err = s.Complete(t.Context(), c.ID, r.Revision, owner, now, contract.Status{State: "failed", FailureCode: "ca_unavailable"}, nil); err != nil {
		t.Fatal(err)
	}
	retained, err := s.Material(t.Context(), c.ID)
	if err != nil || !bytes.Equal(retained.CertificatePEM, m.CertificatePEM) || !bytes.Equal(retained.PrivateKey.Bytes(), m.PrivateKey.Bytes()) {
		t.Fatal("failure replaced old material", err)
	}
	owner = uuid.New().String()
	ok, err = s.Acquire(t.Context(), c.ID, r.Revision, owner, now, time.Minute)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	c.Name = "New name"
	updated, err := s.Save(t.Context(), c, r.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != r.Revision+1 {
		t.Fatal(updated.Revision)
	}
	if err = s.Complete(t.Context(), c.ID, r.Revision, owner, now, contract.Status{State: "ready"}, &m); !errors.Is(err, ErrConflict) {
		t.Fatal("stale revision published", err)
	}
	if _, err = s.Save(t.Context(), c, r.Revision); !errors.Is(err, ErrConflict) {
		t.Fatal("stale configuration saved", err)
	}
}

func TestReferenceProtectionAndConfigurationExport(t *testing.T) {
	s, db, c := fixture(t)
	r, err := s.Save(t.Context(), c, 0)
	if err != nil {
		t.Fatal(err)
	}
	accountKey := NewSecret([]byte("account-private-marker"))
	if _, err = s.AccountKey(t.Context(), c.DirectoryURL, c.Email, accountKey); err != nil {
		t.Fatal(err)
	}
	tx, err := db.DB().BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = ReplaceReferences(t.Context(), tx, "gateway", "listener", "Public HTTPS", []string{c.ID}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = s.Delete(t.Context(), c.ID, r.Revision); !errors.Is(err, ErrInUse) {
		t.Fatal("referenced certificate deleted", err)
	}
	c.Domains = []string{"other.example"}
	if _, err = s.Save(t.Context(), c, r.Revision); !errors.Is(err, ErrInUse) {
		t.Fatal("referenced identities changed", err)
	}
	refs, err := s.References(t.Context(), c.ID)
	if err != nil || len(refs) != 1 || refs[0].Name != "Public HTTPS" {
		t.Fatal(refs, err)
	}
	export, err := sqlite.ExportConfig(t.Context(), db.DB())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(export, []byte("account-private-marker")) || bytes.Contains(export, []byte("certificate_acme_accounts")) || bytes.Contains(export, []byte("managed_certificate_material")) {
		t.Fatal("private certificate tables entered config export")
	}
	// A losing registration candidate must not replace the durable account key.
	account, err := s.AccountKey(t.Context(), c.DirectoryURL, c.Email, NewSecret([]byte("losing-key")))
	if err != nil || !bytes.Equal(account.Key.Bytes(), accountKey.Bytes()) {
		t.Fatal("account key replaced", err)
	}
}

func TestSecretDoesNotSerializeOrFormat(t *testing.T) {
	s := NewSecret([]byte("do-not-log-private-key"))
	encoded, err := json.Marshal(struct{ Secret Secret }{s})
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{string(encoded), fmt.Sprint(s), fmt.Sprintf("%+v", s), fmt.Sprintf("%#v", s)} {
		if bytes.Contains([]byte(text), s.Bytes()) {
			t.Fatal("secret escaped projection")
		}
	}
	copy := s.Bytes()
	clear(copy)
	if s.Empty() || string(s.Bytes()) != "do-not-log-private-key" {
		t.Fatal("caller mutated private storage")
	}
}

func TestExpiredLeaseCannotPublish(t *testing.T) {
	s, _, c := fixture(t)
	r, err := s.Save(t.Context(), c, 0)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	old := uuid.New().String()
	next := uuid.New().String()
	if ok, err := s.Acquire(t.Context(), c.ID, r.Revision, old, now, time.Second); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if ok, err := s.Acquire(t.Context(), c.ID, r.Revision, next, now.Add(time.Second), time.Minute); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if err := s.Complete(t.Context(), c.ID, r.Revision, old, now.Add(time.Second), contract.Status{State: "ready"}, nil); !errors.Is(err, ErrConflict) {
		t.Fatal("expired job published", err)
	}
	if err := s.Complete(t.Context(), c.ID, r.Revision, next, now.Add(time.Second), contract.Status{State: "failed"}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestWALSnapshotIncludesPrivateCertificateAccounts(t *testing.T) {
	s, db, c := fixture(t)
	private := NewSecret([]byte("snapshot-account-private-marker"))
	if _, err := s.AccountKey(t.Context(), c.DirectoryURL, c.Email, private); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "snapshot.db")
	version, err := sqlite.SnapshotRecoveryDatabase(t.Context(), db.Path(), path, "configuration", 64<<20)
	latest, versionErr := sqlite.SupportedSchemaVersion("configuration")
	if err != nil || versionErr != nil || version != latest {
		t.Fatal(version, err)
	}
	reader, err := sqlite.OpenSnapshotReader(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var copied []byte
	if err := reader.QueryRowContext(t.Context(), `SELECT private_key_pem FROM certificate_acme_accounts WHERE directory=? AND email=?`, c.DirectoryURL, c.Email).Scan(&copied); err != nil || !bytes.Equal(copied, private.Bytes()) {
		t.Fatal("coherent snapshot lost account key", err)
	}
}
