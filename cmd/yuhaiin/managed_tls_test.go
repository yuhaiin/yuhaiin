package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"filippo.io/age"
	"github.com/Asutorufa/yuhaiin/cmd/yuhaiin/internal/startuphealth"
	recovery "github.com/Asutorufa/yuhaiin/pkg/app/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/cert"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	managementtls "github.com/Asutorufa/yuhaiin/pkg/management/tls"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	archive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
	"github.com/Asutorufa/yuhaiin/pkg/store/certificates"
)

func TestManagedManagementTLSActualStartupAndRestore(t *testing.T) {
	const actionEnv = "YUH_MANAGED_TLS_ACTION"
	const directoryEnv = "YUH_MANAGED_TLS_DIRECTORY"
	const idEnv = "YUH_MANAGED_TLS_ID"
	const proofEnv = "YUH_MANAGED_TLS_PROOF"
	if action := os.Getenv(actionEnv); action != "" {
		directory, id := os.Getenv(directoryEnv), os.Getenv(idEnv)
		wait = func(ctx context.Context, listeners ...net.Listener) error {
			var pair tls.Certificate
			if action == "clone" {
				value, _, _, err := managementtls.LoadOrCreate(directory, nil)
				if err != nil {
					return err
				}
				pair = value
			} else {
				data, err := os.ReadFile(os.Getenv(proofEnv))
				if err != nil {
					return err
				}
				block, _ := pem.Decode(data)
				if block == nil {
					return errors.New("missing public proof")
				}
				pair.Certificate = [][]byte{block.Bytes}
			}
			if err := startuphealth.CheckListener(ctx, listeners[0].Addr(), &pair); err != nil {
				return err
			}
			if action == "ari" || action == "ari_blocked" {
				reader, err := sqlite.OpenLiveReader(ctx, filepath.Join(directory, "state.db"))
				if err != nil {
					return err
				}
				defer reader.Close()
				timer := time.NewTicker(10 * time.Millisecond)
				defer timer.Stop()
				bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()
				for {
					r, err := certificates.New(reader).Get(bounded, id)
					if err != nil {
						return err
					}
					expected := "available"
					if action == "ari_blocked" {
						expected = "unavailable"
					}
					if r.Status.RenewalInfo != nil && r.Status.RenewalInfo.State == expected {
						return nil
					}
					select {
					case <-bounded.Done():
						return fmt.Errorf("production ARI did not publish advice: %w", bounded.Err())
					case <-timer.C:
					}
				}
			}
			return nil
		}
		args := []string{"-path", directory, "-host", "127.0.0.1:0", "-https-certificate-id", id}
		if action == "restore" || action == "clone" {
			args = []string{"-path", directory, "-host", "127.0.0.1:1", "-https=false"}
		}
		err := run(args)
		if action == "missing" {
			if err == nil || !strings.Contains(err.Error(), "already issued") {
				t.Fatal("missing certificate did not fail closed", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		return
	}
	if runtime.GOOS == "windows" {
		t.Skip("restore activation requires directory synchronization")
	}
	t.Setenv("EXTERNAL_WEB", "")
	source := recoveryServiceDeployment(t, "managed-tls", "")
	ca, err := cert.GenerateCa()
	if err != nil {
		t.Fatal(err)
	}
	roots, err := ca.CertBytes()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.GenerateServerCert("management.example")
	if err != nil {
		t.Fatal(err)
	}
	chain, err := leaf.CertBytes()
	if err != nil {
		t.Fatal(err)
	}
	private, err := leaf.PrivateKeyBytes()
	if err != nil {
		t.Fatal(err)
	}
	proof := filepath.Join(t.TempDir(), "public-leaf.pem")
	if err := os.WriteFile(proof, chain, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sqlite.Open(t.Context(), filepath.Join(source, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	var ariRequests atomic.Int32
	ariServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ariRequests.Add(1)
		if r.URL.Path == "/directory" {
			_ = json.MarshalWrite(w, map[string]string{"renewalInfo": "https://" + r.Host + "/ari"})
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/ari/") {
			t.Error("unexpected production CA request", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Retry-After", "21600")
		_ = json.MarshalWrite(w, map[string]any{"suggestedWindow": map[string]time.Time{"start": time.Now().Add(12 * time.Hour), "end": time.Now().Add(24 * time.Hour)}})
	}))
	defer ariServer.Close()
	roots = append(roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ariServer.Certificate().Raw})...)
	// This fixture tests a blocked CA before explicitly permitting its route.
	// A deployment with no selected proxy must never receive a Direct fallback.
	policyRule := contractroute.RouteRule{ID: uuid.New().String(), Name: "Local test CA", Mode: "block", Rules: []contractroute.RuleExpr{{Type: "always", Always: &contractroute.MatchAllExpr{}}}}
	if err := plainstore.NewRouteRuleStore(db.DB()).SaveRule(t.Context(), policyRule, 1, 0); err != nil {
		t.Fatal(err)
	}
	store := certificates.New(db.DB())
	cfg := contract.Config{ID: uuid.New().String(), Name: "Management", Domains: []string{"management.example"}, DirectoryURL: ariServer.URL + "/directory", Email: "ops@example.com", TermsAccepted: true, TrustPEM: string(roots), Challenge: contract.Challenge{Type: "http-01", HTTPGatewayID: uuid.New().String()}}
	resource, err := store.Save(t.Context(), cfg, 0)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	owner := uuid.New().String()
	if ok, err := store.Acquire(t.Context(), cfg.ID, resource.Revision, owner, now, time.Minute); err != nil || !ok {
		t.Fatal(ok, err)
	}
	block, _ := pem.Decode(chain)
	if block == nil {
		t.Fatal("leaf PEM missing")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Complete(t.Context(), cfg.ID, resource.Revision, owner, now, contract.Status{State: "ready", Serial: parsed.SerialNumber.String(), NotBefore: parsed.NotBefore, NotAfter: parsed.NotAfter, NextAttempt: now.Add(24 * time.Hour), LastAttempt: now, LastSuccess: now}, &certificates.Material{CertificatePEM: chain, PrivateKey: certificates.NewSecret(private)}); err != nil {
		t.Fatal(err)
	}
	options, err := backupstore.New(db.DB()).Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	options.Recovery = &contractrecovery.Policy{LocalPoints: &contractrecovery.PointRetention{Enabled: true, KeepCount: 1, KeepDays: 1}}
	if err := backupstore.New(db.DB()).Save(t.Context(), options); err != nil {
		t.Fatal(err)
	}
	newestCopy := localPointStartupFixture(t, source, time.Now().Add(-time.Hour))
	expiredCopy := localPointStartupFixture(t, source, time.Now().Add(-48*time.Hour))
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	invoke := func(t *testing.T, action, directory string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestManagedManagementTLSActualStartupAndRestore$", "-test.v")
		cmd.Env = append(os.Environ(), actionEnv+"="+action, directoryEnv+"="+directory, idEnv+"="+cfg.ID, proofEnv+"="+proof)
		if logs, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("managed TLS %s: %v\n%s", action, err, logs)
		}
	}
	invoke(t, "start", source)
	if _, err := os.Stat(filepath.Join(source, ".recovery-point-"+expiredCopy)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("actual startup did not apply saved local retention", err)
	}
	if _, err := os.Stat(filepath.Join(source, ".recovery-point-"+newestCopy)); err != nil {
		t.Fatal("startup removed the newest rollback copy", err)
	}
	invoke(t, "restart", source)
	db, err = sqlite.Open(t.Context(), filepath.Join(source, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	store = certificates.New(db.DB())
	cfg.AutoRenew = true
	if _, err := store.Save(t.Context(), cfg, resource.Revision); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	invoke(t, "ari_blocked", source)
	if ariRequests.Load() != 0 {
		t.Fatal("background ARI bypassed routing denial", ariRequests.Load())
	}
	db, err = sqlite.Open(t.Context(), filepath.Join(source, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	policyRule.Mode = "direct"
	if err := plainstore.NewRouteRuleStore(db.DB()).SaveRule(t.Context(), policyRule, 1, 0); err != nil {
		t.Fatal(err)
	}
	store = certificates.New(db.DB())
	current, err := store.Get(t.Context(), cfg.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Start a fresh metadata fixture after the denied-route case. Production
	// retries retain their persisted backoff, covered by the clock-driven suite.
	current.Status.RenewalInfo = nil
	owner = uuid.New().String()
	now = time.Now()
	if ok, err := store.Acquire(t.Context(), cfg.ID, current.Revision, owner, now, time.Minute); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if err := store.Complete(t.Context(), cfg.ID, current.Revision, owner, now, current.Status, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	invoke(t, "ari", source)
	if ariRequests.Load() != 2 {
		t.Fatal("production worker did not use governed CA directory/ARI requests", ariRequests.Load())
	}
	db, err = sqlite.Open(t.Context(), filepath.Join(source, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := backupstore.LoadRecoveryRuntime(t.Context(), db.DB())
	if err != nil || inputs == nil || inputs.ManagementTLS != "managed" || inputs.ManagedCertificateID != cfg.ID {
		t.Fatal("runtime does not record actual managed identity", inputs, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "managed.yhb")
	manifest, err := recovery.Create(t.Context(), source, path, archive.Encryption{Recipient: key.Recipient().String()}, recovery.CreateOptions{ConfirmedMaintenance: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"original", "clone"} {
		t.Run(mode, func(t *testing.T) {
			target := t.TempDir()
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			result, err := recovery.Restore(t.Context(), target, file, archive.Decryption{Identity: key.String()}, recovery.RestoreOptions{Mode: mode, ConfirmedMaintenance: true, ConfirmBackupID: manifest.ID, ConfirmSourceInstanceID: manifest.InstanceID, ConfirmTargetInstanceID: "empty", ConfirmSourceStopped: true, ConfirmCredentialRevival: true, AdoptStartup: true})
			if err != nil {
				t.Fatal(err)
			}
			action := "restore"
			if mode == "clone" {
				action = "clone"
				if result.Runtime.ManagementTLS != "self_signed" || result.Runtime.ManagedCertificateID != "" {
					t.Fatal("clone reused source identity", result.Runtime)
				}
			}
			invoke(t, action, target)
		})
	}
	if ariRequests.Load() != 2 {
		t.Fatal("restart/restore ignored the persisted ARI deadline", ariRequests.Load())
	}

	db, err = sqlite.Open(t.Context(), filepath.Join(source, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().ExecContext(t.Context(), "DELETE FROM managed_certificate_material"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	invoke(t, "missing", source)
}

func TestManagedManagementTLSRejectsAmbiguousFlags(t *testing.T) {
	for _, args := range [][]string{
		{"-https=false"}, {"-https-cert", "site.pem", "-https-key", "site.key"}, {"-https-names", "site.example"},
	} {
		args = append(args, "-https-certificate-id", uuid.New().String(), "-path", t.TempDir())
		if err := run(args); err == nil || !strings.Contains(err.Error(), "excludes") {
			t.Fatal("ambiguous TLS source accepted", args, err)
		}
	}
}

// This is a private on-disk history fixture, not an archive or live SQLite DB.
func localPointStartupFixture(t *testing.T, directory string, created time.Time) string {
	t.Helper()
	id := uuid.New().String()
	data := []byte("private rollback-copy fixture")
	digest := sha256.Sum256(data)
	metadata := map[string]any{"version": 1, "id": id, "backupId": uuid.New().String(), "instanceId": uuid.New().String(), "createdAt": created, "phase": "committed", "stage": ".recovery-stage-fixture", "runtime": contractrecovery.Runtime{ManagementTLS: "disabled", WorkingDirectory: directory}, "moves": []map[string]any{{"path": "state.db", "hadOriginal": true, "originalSha256": hex.EncodeToString(digest[:])}}}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	point := filepath.Join(directory, ".recovery-point-"+id)
	if err := os.MkdirAll(filepath.Join(point, ".recovery-meta"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(point, "state.db"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(point, ".recovery-meta", "transaction.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return id
}
