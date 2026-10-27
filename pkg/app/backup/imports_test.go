package backup

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
	backupfs "github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/backupfs"
	testfixture "github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/testfixture"
	recovery "github.com/Asutorufa/yuhaiin/pkg/app/backup/recovery"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	managementauth "github.com/Asutorufa/yuhaiin/pkg/management/auth"
	"github.com/Asutorufa/yuhaiin/pkg/s3"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	backuparchive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
)

func recoveryImportFixture(t *testing.T) (*Backup, []byte, *age.X25519Identity, *sqlite.Store) {
	t.Helper()
	directory, key := testfixture.Deployment(t)
	archive := filepath.Join(t.TempDir(), "deployment.yhb")
	if _, err := recovery.Create(t.Context(), directory, archive, backuparchive.Encryption{Recipient: key.Recipient().String()}, recovery.CreateOptions{ConfirmedMaintenance: true}); err != nil {
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
	return &Backup{store: backupstore.New(db.DB()), dir: directory}, data, key, db
}

func TestRecoveryImportPreviewIsPrivateBoundedAndDoesNotActivate(t *testing.T) {
	for _, mode := range []string{"original", "clone"} {
		t.Run(mode, func(t *testing.T) {
			b, data, key, db := recoveryImportFixture(t)
			ctx := managementauth.WithPrincipal(t.Context(), managementauth.Principal{UserID: "owner"})
			before, err := sqlite.RecoveryInstanceID(ctx, filepath.Join(b.dir, "state.db"), false)
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
			name, _ := backupfs.ImportPath(item.ID)
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
			after, err := sqlite.RecoveryInstanceID(ctx, filepath.Join(b.dir, "state.db"), false)
			if err != nil || after != before {
				t.Fatal("preview changed the active deployment identity", err)
			}
			actualCertificate, err := os.ReadFile(filepath.Join(b.dir, "management-tls.pem"))
			if err != nil || !bytes.Equal(actualCertificate, certificate) {
				t.Fatal("preview changed active management TLS", err)
			}
			if _, err := os.Lstat(filepath.Join(b.dir, ".recovery-transaction.json")); !errors.Is(err, os.ErrNotExist) {
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
	name, _ := backupfs.ImportPath(item.ID)
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

type recoveryImportReadFunc func([]byte) (int, error)

func (f recoveryImportReadFunc) Read(data []byte) (int, error) { return f(data) }

func TestRecoveryFailedUploadFreesFilesWhenRegistryWritesAreUnavailable(t *testing.T) {
	b, _, _, db := recoveryImportFixture(t)
	namespace := filepath.Join(b.dir, ".recovery-imports")
	if err := os.MkdirAll(namespace, 0o700); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(namespace, "unrelated.keep")
	if err := os.WriteFile(keep, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	reader := recoveryImportReadFunc(func(data []byte) (int, error) {
		if err := db.Close(); err != nil {
			return 0, err
		}
		data[0] = 'x'
		return 1, errors.New("fixture body failure after registry became unavailable")
	})
	if _, err := b.UploadRecoveryImport(t.Context(), io.NopCloser(reader), -1); err == nil {
		t.Fatal("failed request body accepted")
	}
	entries, err := os.ReadDir(namespace)
	if err != nil || len(entries) != 1 || entries[0].Name() != "unrelated.keep" {
		t.Fatal("unpublished ciphertext survived a registry failure or unrelated data was removed", err)
	}
	reopened, err := sqlite.Open(t.Context(), filepath.Join(b.dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	resumed := &Backup{store: backupstore.New(reopened.DB()), dir: b.dir}
	if err := resumed.pruneRecoveryImportsLocked(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if ids, err := resumed.store.RecoveryImportIDs(t.Context()); err != nil || len(ids) != 0 {
		t.Fatal("startup did not reconcile the interrupted registry record", err)
	}
}

func TestRecoveryImportRejectsAliasedNamespaceWithoutRemovingOtherFiles(t *testing.T) {
	b, data, _, _ := recoveryImportFixture(t)
	protected := filepath.Join(b.dir, "existing-assets")
	if err := os.Mkdir(protected, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(protected, "identity.keep")
	if err := os.WriteFile(sentinel, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("existing-assets", filepath.Join(b.dir, ".recovery-imports")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.UploadRecoveryImport(t.Context(), io.NopCloser(bytes.NewReader(data)), int64(len(data))); err == nil {
		t.Fatal("upload followed an aliased private namespace")
	}
	if value, err := os.ReadFile(sentinel); err != nil || string(value) != "preserve" {
		t.Fatal("rejected upload changed unrelated identity material", err)
	}
	if ids, err := b.store.RecoveryImportIDs(t.Context()); err != nil || len(ids) != 0 {
		t.Fatal("rejected namespace consumed a registry slot", err)
	}
}

func TestRecoveryImportCountAndStreamBudgetAreHardBounds(t *testing.T) {
	b, data, _, _ := recoveryImportFixture(t)
	for range backupstore.MaxRecoveryImports {
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
	if err := b.store.AddRecoveryImport(t.Context(), backupstore.RecoveryImportRecord{ID: uuid.New().String(), Owner: "local-management", CreatedAt: now, ExpiresAt: now.Add(recoveryImportLifetime), State: "uploading"}); err != nil {
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
	directory, key := testfixture.Deployment(t)
	db, err := sqlite.Open(t.Context(), filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	owner := backupstore.New(db.DB())
	now := time.Now().UTC()
	item := backupstore.RecoveryImportRecord{ID: uuid.New().String(), Owner: "fixture", State: "uploading", CreatedAt: now, ExpiresAt: now.Add(recoveryImportLifetime)}
	if err := owner.AddRecoveryImport(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "history.yhb")
	if _, err := recovery.Create(t.Context(), directory, archive, backuparchive.Encryption{Recipient: key.Recipient().String()}, recovery.CreateOptions{ConfirmedMaintenance: true, IncludeHistory: true}); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	prepared, err := backuparchive.Prepare(t.Context(), source, t.TempDir(), backuparchive.Decryption{Identity: key.String()})
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
