package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"filippo.io/age"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	managementauth "github.com/Asutorufa/yuhaiin/pkg/management/auth"
	"github.com/Asutorufa/yuhaiin/pkg/s3"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
)

func recoveryImportFixture(t *testing.T) (*Backup, []byte, *age.X25519Identity, *sqlite.Store) {
	t.Helper()
	directory, key := recoveryDeployment(t)
	archive := filepath.Join(t.TempDir(), "deployment.yhb")
	if _, err := CreateOfflineRecovery(t.Context(), directory, archive, store.RecoveryEncryption{Recipient: key.Recipient().String()}, RecoveryCreateOptions{ConfirmedMaintenance: true}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sqlite.Open(t.Context(), filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &Backup{store: store.NewBackupStore(db.DB()), dir: directory}, data, key, db
}

func TestRecoveryImportPreviewIsPrivateBoundedAndDoesNotActivate(t *testing.T) {
	for _, mode := range []string{"original", "clone"} {
		t.Run(mode, func(t *testing.T) {
			b, data, key, db := recoveryImportFixture(t)
			ctx := managementauth.WithPrincipal(t.Context(), managementauth.Principal{UserID: "owner"})
			before, err := recoveryTargetID(ctx, b.dir)
			if err != nil {
				t.Fatal(err)
			}
			certificate, err := os.ReadFile(filepath.Join(b.dir, "management-tls.pem"))
			if err != nil {
				t.Fatal(err)
			}
			item, err := b.UploadRecoveryImport(ctx, io.NopCloser(bytes.NewReader(data)), int64(len(data)))
			if err != nil || item.State != "uploaded" || item.Size != int64(len(data)) || item.SHA256 == "" {
				t.Fatal("upload was not durably recorded", err)
			}
			name, _ := recoveryImportPath(item.ID)
			info, err := os.Stat(filepath.Join(b.dir, name))
			if err != nil || info.Mode().Perm()&0o077 != 0 {
				t.Fatal("upload is not private", err)
			}
			wrong, err := age.GenerateX25519Identity()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := b.PreviewRecoveryImport(ctx, contract.RecoveryImportPreviewRequest{ID: item.ID, Mode: mode, Identity: wrong.String()}); err == nil || strings.Contains(err.Error(), wrong.String()) {
				t.Fatal("wrong key accepted or exposed")
			}
			item, err = b.PreviewRecoveryImport(ctx, contract.RecoveryImportPreviewRequest{ID: item.ID, Mode: mode, Identity: key.String()})
			if err != nil || item.Preview == nil || item.State != "previewed" || len(item.Preview.Files) == 0 || item.Preview.TargetInstanceID != before {
				t.Fatal("authenticated deployment preview unavailable", err)
			}
			if mode == "clone" && item.Preview.InstanceID == before {
				t.Fatal("clone preview reused the source instance identifier")
			}
			after, err := recoveryTargetID(ctx, b.dir)
			if err != nil || after != before {
				t.Fatal("preview changed the active deployment identity", err)
			}
			actualCertificate, err := os.ReadFile(filepath.Join(b.dir, "management-tls.pem"))
			if err != nil || !bytes.Equal(actualCertificate, certificate) {
				t.Fatal("preview changed active management TLS", err)
			}
			if transaction, err := readRecoveryTransaction(b.dir); err != nil || transaction != nil {
				t.Fatal("preview activated a file transaction", err)
			}
			row, err := b.store.RecoveryImport(ctx, item.ID)
			if err != nil || strings.Contains(row.Plan, key.String()) || strings.Contains(row.Plan, wrong.String()) {
				t.Fatal("private decryption input persisted", err)
			}
			if !strings.HasPrefix(row.Stage, filepath.Join(".recovery-imports", item.ID)+string(filepath.Separator)) {
				t.Fatal("plaintext staging escaped the immutable import container")
			}
			if err := filepath.WalkDir(filepath.Join(b.dir, row.Stage), func(_ string, entry os.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				info, err := entry.Info()
				if err != nil {
					return err
				}
				if info.Mode().Perm()&0o077 != 0 {
					return errors.New("private staging has group/world permissions")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			// Read the live owner so committed WAL records are included. The
			// immutable snapshot reader intentionally ignores a live WAL.
			var metadata string
			err = db.DB().QueryRowContext(ctx, "SELECT data_json FROM backup_recovery_imports WHERE id=?", item.ID).Scan(&metadata)
			if err != nil || strings.Contains(metadata, key.String()) || strings.Contains(metadata, wrong.String()) {
				t.Fatal("private preview input reached persistent metadata", err)
			}
			foreign := managementauth.WithPrincipal(t.Context(), managementauth.Principal{UserID: "another-manager"})
			if list, err := b.RecoveryImports(foreign); err != nil || len(list) != 0 {
				t.Fatal("another principal saw the staged identity inventory", err)
			}
			if _, err := b.PreviewRecoveryImport(foreign, contract.RecoveryImportPreviewRequest{ID: item.ID, Mode: mode, Identity: key.String()}); err == nil {
				t.Fatal("another principal opened the staged archive")
			}
			if err := b.DiscardRecoveryImport(foreign, item.ID); err == nil {
				t.Fatal("another principal discarded the staged archive")
			}
			if err := b.DiscardRecoveryImport(ctx, item.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(b.dir, filepath.Dir(name))); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("discard retained ciphertext or plaintext staging", err)
			}
		})
	}
}

func TestRecoveryImportRejectsSizeTamperingAndExpiresOwnedStaging(t *testing.T) {
	b, data, key, _ := recoveryImportFixture(t)
	for _, size := range []int64{0, -2, s3.MaxObjectBytes + 1, int64(len(data)) + 1} {
		if _, err := b.UploadRecoveryImport(t.Context(), io.NopCloser(bytes.NewReader(data)), size); err == nil {
			t.Fatal("invalid or truncated upload accepted", size)
		}
	}
	if ids, err := b.store.RecoveryImportIDs(t.Context()); err != nil || len(ids) != 0 {
		t.Fatal("failed upload left a registry slot", err)
	}
	item, err := b.UploadRecoveryImport(t.Context(), io.NopCloser(bytes.NewReader(data)), -1)
	if err != nil {
		t.Fatal(err)
	}
	name, _ := recoveryImportPath(item.ID)
	if err := os.WriteFile(filepath.Join(b.dir, name), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := b.PreviewRecoveryImport(t.Context(), contract.RecoveryImportPreviewRequest{ID: item.ID, Mode: "original", Identity: key.String()}); err == nil {
		t.Fatal("changed ciphertext reached preview")
	}
	row, err := b.store.RecoveryImport(t.Context(), item.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Model a process dying after decryption but before saving its stage name.
	orphan := filepath.Join(b.dir, filepath.Dir(name), ".recovery-stage-interrupted")
	if err := os.Mkdir(orphan, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(orphan, "private-data"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	row.ExpiresAt = time.Now().Add(-time.Second)
	if err := b.store.SaveRecoveryImport(t.Context(), row, row.State); err != nil {
		t.Fatal(err)
	}
	if err := b.pruneRecoveryImports(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("expired interrupted plaintext staging survived", err)
	}
	if ids, err := b.store.RecoveryImportIDs(t.Context()); err != nil || len(ids) != 0 {
		t.Fatal("expired upload retained its slot", err)
	}
}

type recoveryNotifyingReader struct {
	io.ReadCloser
	started chan struct{}
	once    sync.Once
}

func (r *recoveryNotifyingReader) Read(data []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	return r.ReadCloser.Read(data)
}

func TestRecoveryImportCancellationClosesBlockedRequestAndReleasesSlot(t *testing.T) {
	b, _, _, _ := recoveryImportFixture(t)
	lifetime, cancel := context.WithCancel(t.Context())
	defer cancel()
	b.ctx = lifetime
	reader, writer := io.Pipe()
	defer writer.Close()
	input := &recoveryNotifyingReader{ReadCloser: reader, started: make(chan struct{})}
	result := make(chan error, 1)
	go func() { _, err := b.UploadRecoveryImport(t.Context(), input, -1); result <- err }()
	select {
	case <-input.started:
	case <-time.After(2 * time.Second):
		t.Fatal("upload did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation did not release the blocked body read", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled upload retained the backup lease")
	}
	if ids, err := b.store.RecoveryImportIDs(t.Context()); err != nil || len(ids) != 0 {
		t.Fatal("cancelled upload retained its registry slot", err)
	}
}

func TestRecoveryImportCountAndStreamBudgetAreHardBounds(t *testing.T) {
	b, data, _, _ := recoveryImportFixture(t)
	for range store.MaxRecoveryImports {
		if _, err := b.UploadRecoveryImport(t.Context(), io.NopCloser(bytes.NewReader(data)), int64(len(data))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.UploadRecoveryImport(t.Context(), io.NopCloser(bytes.NewReader(data)), int64(len(data))); err == nil {
		t.Fatal("unbounded import registry")
	}
	input := bytes.NewReader(bytes.Repeat([]byte("x"), 128))
	var output bytes.Buffer
	if _, err := copyRecoveryImport(t.Context(), input, &output, 8, func(int64) error { return nil }); err == nil || input.Len() < 119 || output.Len() > 8 {
		t.Fatal("chunked upload exceeded its input/output budget", err, input.Len(), output.Len())
	}
}

func TestRecoveryIdleRetentionDoesNotCompeteWithManualControlWork(t *testing.T) {
	b, _, _, _ := recoveryImportFixture(t)
	options, err := b.store.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	options.Recovery = &contract.RecoveryPolicy{Target: "local", KeepCount: 1, KeepDays: 1}
	if err := b.store.Save(t.Context(), options); err != nil {
		t.Fatal(err)
	}
	queuedArchiveFixture(t, b, "local", time.Now())
	now := time.Now().UTC()
	if err := b.store.AddRecoveryImport(t.Context(), store.RecoveryImportRecord{ID: uuid.New().String(), Owner: "local-management", CreatedAt: now, ExpiresAt: now.Add(recoveryImportLifetime), State: "uploading"}); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.pruneRecoveryImports(t.Context()); err != nil {
		t.Error("unexpired import cleanup contended with a manual operation", err)
	}
	if err := b.pruneRecoveryBackups(t.Context()); err != nil {
		t.Error("retention of the only successful point contended with a manual operation", err)
	}
}

func TestFullRecoveryNeverCarriesEphemeralImportsEvenWithHistory(t *testing.T) {
	directory, key := recoveryDeployment(t)
	db, err := sqlite.Open(t.Context(), filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	owner := store.NewBackupStore(db.DB())
	now := time.Now().UTC()
	item := store.RecoveryImportRecord{ID: uuid.New().String(), Owner: "fixture", State: "uploading", CreatedAt: now, ExpiresAt: now.Add(recoveryImportLifetime)}
	if err := owner.AddRecoveryImport(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "history.yhb")
	if _, err := CreateOfflineRecovery(t.Context(), directory, archive, store.RecoveryEncryption{Recipient: key.Recipient().String()}, RecoveryCreateOptions{ConfirmedMaintenance: true, IncludeHistory: true}); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	prepared, err := store.PrepareRecoveryArchive(t.Context(), source, t.TempDir(), store.RecoveryDecryption{Identity: key.String()})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	for _, target := range []struct {
		path  string
		count int
	}{
		{filepath.Join(prepared.Directory(), "state.db"), 0},
		{filepath.Join(directory, "state.db"), 1},
	} {
		reader, err := sqlite.OpenSnapshotReader(t.Context(), target.path)
		if err != nil {
			t.Fatal(err)
		}
		var count int
		err = reader.QueryRowContext(t.Context(), "SELECT count(*) FROM backup_recovery_imports").Scan(&count)
		_ = reader.Close()
		if err != nil || count != target.count {
			t.Fatal("ephemeral staging leaked into the archive or source was changed", count, err)
		}
	}
}
