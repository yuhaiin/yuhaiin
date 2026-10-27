package backup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"filippo.io/age"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
)

// Transfer/retention unit fixtures omit the scheduler so setup cannot race
// automatic startup recovery/retention. The real scheduler and installed host
// are exercised by dedicated lifecycle and systemd integration tests.
func recoveryTransferBackup(t *testing.T, handler http.HandlerFunc) (*Backup, *backupstore.Store) {
	t.Helper()
	directory := t.TempDir()
	db, err := sqlite.Open(t.Context(), filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	owner := backupstore.New(db.DB())
	if err := owner.Save(t.Context(), contract.Option{InstanceName: "fixture", S3: contract.S3{Enabled: true, EndpointURL: server.URL, Bucket: "backups", AccessKey: "access", SecretKey: "secret"}}); err != nil {
		t.Fatal(err)
	}
	return &Backup{store: owner, dir: directory, proxy: direct.Default}, owner
}

func queuedArchiveFixture(t *testing.T, b *Backup, target string, created time.Time) backupstore.RecoveryJob {
	t.Helper()
	options, err := b.store.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := backupstore.NormalizeRecoveryPolicy(contract.RecoveryPolicy{Target: target, Recipient: identity.Recipient().String(), AllowMaintenance: true, TimeoutMinutes: 1})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := recoveryS3Digest(options.S3)
	if err != nil {
		t.Fatal(err)
	}
	job := backupstore.RecoveryJob{ID: uuid.New().String(), BackupID: uuid.New().String(), InstanceID: uuid.New().String(), State: "queued", Target: target, CreatedAt: created, Policy: policy, S3Digest: digest}
	if err := b.store.EnqueueRecovery(t.Context(), job); err != nil {
		t.Fatal(err)
	}
	path, _ := recoveryArchivePath(b.dir, job.ID)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	// This test isolates opaque encrypted-file transfer, not the age codec.
	if err := os.WriteFile(path, bytes.Repeat([]byte("opaque-archive-fixture"), 100), 0600); err != nil {
		t.Fatal(err)
	}
	job.Size, job.SHA256, err = digestRecoveryArchive(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	job.State, job.Verification = "local_ready", "ciphertext_sha256"
	job.ObjectKey = "recovery/" + job.InstanceID + "/" + job.BackupID + ".yhb"
	if err := b.store.SaveRecoveryJob(t.Context(), job, "queued"); err != nil {
		t.Fatal(err)
	}
	return job
}

func TestRecoveryUploadRequiresMatchingCiphertextReadback(t *testing.T) {
	for _, fault := range []string{"none", "corrupt", "truncated", "destination-changed", "local-changed", "cancel"} {
		t.Run(fault, func(t *testing.T) {
			var mu sync.Mutex
			var object []byte
			requests := 0
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			b, owner := recoveryTransferBackup(t, func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				requests++
				if r.Method == http.MethodPut {
					if fault == "cancel" {
						cancel()
						return
					}
					object, _ = io.ReadAll(r.Body)
					return
				}
				data := object
				if fault == "corrupt" {
					data = bytes.Repeat([]byte("!"), len(object))
				}
				if fault == "truncated" {
					data = data[:len(data)/2]
				}
				_, _ = w.Write(data)
			})
			job := queuedArchiveFixture(t, b, "s3", time.Now())
			if fault == "destination-changed" {
				options, err := owner.Get(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				options.S3.Bucket = "changed"
				if err := owner.Save(t.Context(), options); err != nil {
					t.Fatal(err)
				}
			}
			if fault == "local-changed" {
				path, _ := recoveryArchivePath(b.dir, job.ID)
				if err := os.WriteFile(path, []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := b.uploadRecoveryBackup(ctx, job)
			current, readErr := owner.RecoveryJob(t.Context(), job.ID)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if fault == "none" {
				if err != nil || current.State != "verified" || current.Verification != "s3_ciphertext_readback" {
					t.Fatal("verified transfer not recorded", err, current.State)
				}
			} else if current.State == "verified" {
				t.Fatal("unverified transfer marked reliable")
			}
			if fault == "corrupt" && (current.State != "failed" || current.ErrorCode != "verification_failed") {
				t.Fatal("corrupt readback not explained", current.State, current.ErrorCode)
			}
			if fault == "cancel" && (current.State != "local_ready" || current.UploadAttempts != 1) {
				t.Fatal("cancelled upload lost its resumable private archive")
			}
			mu.Lock()
			defer mu.Unlock()
			if (fault == "destination-changed" || fault == "local-changed") && requests != 0 {
				t.Fatal("changed destination/archive initiated network IO")
			}
		})
	}
}

func TestRecoveryDownloadLeaseProtectsDeletionAndRecordedObjectOwnership(t *testing.T) {
	var mu sync.Mutex
	var deleted []string
	b, _ := recoveryTransferBackup(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method != http.MethodDelete {
			t.Error("unexpected retention request", r.Method)
		}
		deleted = append(deleted, r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	})
	job := queuedArchiveFixture(t, b, "s3", time.Now())
	job.State = "verified"
	if err := b.store.SaveRecoveryJob(t.Context(), job, "local_ready"); err != nil {
		t.Fatal(err)
	}
	reader, _, err := b.OpenRecoveryBackup(t.Context(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.DeleteRecoveryBackup(t.Context(), job.ID); err == nil {
		t.Fatal("deleted active download")
	}
	if _, err := io.ReadAll(reader); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.DeleteRecoveryBackup(t.Context(), job.ID); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(deleted) != 1 || !strings.HasSuffix(deleted[0], job.ObjectKey) {
		t.Fatal("retention deleted an unowned object", deleted)
	}
	path, _ := recoveryArchivePath(b.dir, job.ID)
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("archive not removed", err)
	}
}

func TestRecoveryDownloadAdmissionIsBoundedAndReleasesExactlyOnce(t *testing.T) {
	b, _ := recoveryTransferBackup(t, func(http.ResponseWriter, *http.Request) { t.Error("local download used network") })
	job := queuedArchiveFixture(t, b, "local", time.Now())
	readers := make([]io.ReadSeekCloser, 0, 4)
	defer func() {
		for _, reader := range readers {
			_ = reader.Close()
		}
	}()
	for range 4 {
		reader, _, err := b.OpenRecoveryBackup(t.Context(), job.ID)
		if err != nil {
			t.Fatal(err)
		}
		readers = append(readers, reader)
	}
	if reader, _, err := b.OpenRecoveryBackup(t.Context(), job.ID); !errors.Is(err, contract.ErrBusy) || reader != nil {
		t.Fatal("fifth active download was admitted", err)
	}
	if err := readers[0].Close(); err != nil {
		t.Fatal(err)
	}
	if err := readers[0].Close(); err != nil {
		t.Fatal(err)
	}
	reader, _, err := b.OpenRecoveryBackup(t.Context(), job.ID)
	if err != nil {
		t.Fatal("closing a download did not release admission", err)
	}
	readers = append(readers, reader)
	if b.activeRecoveryDownloads.Load() != 4 || b.recoveryReaders[job.ID] != 4 {
		t.Fatal("download lease was released more than once")
	}
}

func TestUnusedRecoveryWorkerDoesNotCompeteWithManualConfigurationBackup(t *testing.T) {
	b, _ := recoveryTransferBackup(t, func(http.ResponseWriter, *http.Request) { t.Error("idle worker used network") })
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.resumeRecoveryBackups(t.Context()); err != nil {
		t.Fatal("empty upload queue acquired the manual backup lease", err)
	}
	if err := b.pruneRecoveryBackups(t.Context()); err != nil {
		t.Fatal("unconfigured retention acquired the manual backup lease", err)
	}
	if err := b.pruneRecoveryImports(t.Context()); err != nil {
		t.Fatal("empty restore staging acquired the manual backup lease", err)
	}
}

func TestRecoveryRetentionKeepsLatestPointAndSkipsActiveReaders(t *testing.T) {
	b, owner := recoveryTransferBackup(t, func(http.ResponseWriter, *http.Request) { t.Error("local retention used network") })
	options, err := owner.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	options.Recovery = &contract.RecoveryPolicy{Target: "local", KeepCount: 1, KeepDays: 1}
	if err := owner.Save(t.Context(), options); err != nil {
		t.Fatal(err)
	}
	older := queuedArchiveFixture(t, b, "local", time.Now().Add(-72*time.Hour))
	newest := queuedArchiveFixture(t, b, "local", time.Now().Add(-48*time.Hour))
	reader, _, err := b.OpenRecoveryBackup(t.Context(), older.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.pruneRecoveryBackups(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.RecoveryJob(t.Context(), older.ID); err != nil {
		t.Fatal("retention deleted an active reader")
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.pruneRecoveryBackups(t.Context()); err != nil {
		t.Fatal(err)
	}
	items, err := owner.RecoveryHistory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ID != newest.ID {
		t.Fatal("retention lost the most recent recovery point", len(items))
	}
}
