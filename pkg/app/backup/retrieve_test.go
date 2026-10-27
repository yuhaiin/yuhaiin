package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	backupfs "github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/backupfs"
	testfixture "github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/testfixture"
	"github.com/Asutorufa/yuhaiin/pkg/app/backup/recovery"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	backuparchive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
)

func retrievableFixture(t *testing.T, b *Backup) (backupstore.RecoveryJob, string, []byte) {
	t.Helper()
	job := queuedArchiveFixture(t, b, "s3", time.Now())
	job.State, job.Verification = "verified", "s3_ciphertext_readback"
	if err := b.store.SaveRecoveryJob(t.Context(), job, "local_ready"); err != nil {
		t.Fatal(err)
	}
	path, _ := backupfs.ArchivePath(b.dir, job.ID)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	return job, path, content
}

func TestRecoveryRetrievalPublishesOnlyRecordedCiphertext(t *testing.T) {
	for _, fault := range []string{"none", "corrupt", "truncated", "oversized", "chunked_oversized", "cancel", "provider", "destination", "object_key", "size_budget", "repair", "repair_failed", "permissions"} {
		t.Run(fault, func(t *testing.T) {
			var object []byte
			var requests atomic.Int32
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			b, owner := recoveryTransferBackup(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodGet {
					t.Error("retrieval mutated remote object", r.Method)
				}
				switch fault {
				case "cancel":
					cancel()
					return
				case "provider":
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte("signed-url-secret"))
					return
				case "corrupt", "repair_failed":
					_, _ = w.Write(bytes.Repeat([]byte("!"), len(object)))
					return
				case "truncated":
					_, _ = w.Write(object[:len(object)/2])
					return
				case "oversized":
					_, _ = w.Write(append(bytes.Clone(object), 'x'))
					return
				case "chunked_oversized":
					w.(http.Flusher).Flush()
					_, _ = w.Write(append(bytes.Clone(object), 'x'))
					return
				}
				_, _ = w.Write(object)
			})
			job, path, data := retrievableFixture(t, b)
			object = data
			if fault == "destination" {
				options, _ := owner.Get(t.Context())
				options.S3.SecretKey = "changed"
				if err := owner.Save(t.Context(), options); err != nil {
					t.Fatal(err)
				}
			}
			if fault == "object_key" || fault == "size_budget" {
				if fault == "object_key" {
					job.ObjectKey = "other-owner/archive.yhb"
				} else {
					job.Size = contract.MaxRecoveryDataBytes + 1
				}
				if err := owner.SaveRecoveryJob(t.Context(), job, job.State); err != nil {
					t.Fatal(err)
				}
			}
			repair := fault == "repair" || fault == "repair_failed" || fault == "permissions"
			if repair {
				if err := os.WriteFile(path, []byte("damaged local copy"), 0600); err != nil {
					t.Fatal(err)
				}
				if fault == "permissions" {
					if err := os.WriteFile(path, object, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(path, 0644); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := b.RetrieveRecoveryBackup(ctx, contract.RecoveryRetrieveRequest{ID: job.ID, ConfirmDownload: true}); err == nil {
					t.Fatal("replaced local copy without explicit consent")
				}
			}
			got, err := b.RetrieveRecoveryBackup(ctx, contract.RecoveryRetrieveRequest{ID: job.ID, ConfirmDownload: true, ConfirmReplace: repair})
			success := fault == "none" || fault == "repair" || fault == "permissions"
			current, readErr := owner.RecoveryJob(t.Context(), job.ID)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if current.State != "verified" || current.Verification != job.Verification {
				t.Fatal("retrieval changed original upload evidence", current)
			}
			if current.ArchiveCheck != "" {
				t.Fatal("ciphertext retrieval claimed decryption success")
			}
			if success {
				if err != nil || got.Retrieval != "verified" || current.RetrievedAt.IsZero() || got.LocalState != "present" {
					t.Fatal("retrieval not recorded", err, got)
				}
				actual, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(actual, object) {
					t.Fatal("wrong archive published", err)
				}
				info, _ := os.Stat(path)
				if info.Mode().Perm() != 0600 {
					t.Fatal("archive is not private")
				}
				before := requests.Load()
				if _, err := b.RetrieveRecoveryBackup(ctx, contract.RecoveryRetrieveRequest{ID: job.ID, ConfirmDownload: true}); err != nil || requests.Load() != before {
					t.Fatal("valid existing copy downloaded again", err)
				}
			} else {
				if err == nil || strings.Contains(err.Error(), "signed-url-secret") {
					t.Fatal("failure was lost or leaked provider secrets", err)
				}
				if fault == "repair_failed" {
					actual, err := os.ReadFile(path)
					if err != nil || string(actual) != "damaged local copy" {
						t.Fatal("failed retrieval destroyed original copy", err)
					}
				} else if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("failed retrieval published an archive", err)
				}
				if !current.RetrievedAt.IsZero() {
					t.Fatal("failed transfer recorded successful retrieval time")
				}
			}
			if (fault == "destination" || fault == "object_key" || fault == "size_budget") && requests.Load() != 0 {
				t.Fatal("invalid metadata caused network traffic")
			}
			if _, err := os.Stat(path + ".download"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("temporary download leaked", err)
			}
		})
	}
}

func TestRecoveryRetrievalSharesLeaseAndRuntimeCancellation(t *testing.T) {
	started := make(chan struct{})
	b, owner := recoveryTransferBackup(t, func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() })
	job, _, _ := retrievableFixture(t, b)
	b.ctx, b.cancel = context.WithCancel(t.Context())
	defer b.cancel()
	done := make(chan error, 1)
	go func() {
		_, err := b.RetrieveRecoveryBackup(t.Context(), contract.RecoveryRetrieveRequest{ID: job.ID, ConfirmDownload: true})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("retrieval did not start")
	}
	status, err := b.RecoveryBackups(t.Context())
	if err != nil || status.Items[0].Retrieval != "running" {
		t.Fatal("active retrieval not visible", err)
	}
	if err := b.DeleteRecoveryBackup(t.Context(), job.ID); !errors.Is(err, contract.ErrBusy) {
		t.Fatal("retention entered active retrieval", err)
	}
	if _, _, err := b.OpenRecoveryBackup(t.Context(), job.ID); !errors.Is(err, contract.ErrBusy) {
		t.Fatal("reader entered active publication", err)
	}
	if _, err := b.RetrieveRecoveryBackup(t.Context(), contract.RecoveryRetrieveRequest{ID: job.ID, ConfirmDownload: true}); !errors.Is(err, contract.ErrBusy) {
		t.Fatal("unbounded parallel retrieval", err)
	}
	b.cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runtime shutdown did not cancel retrieval")
	}
	current, err := owner.RecoveryJob(t.Context(), job.ID)
	if err != nil || current.Retrieval != "cancelled" {
		t.Fatal("cancellation not durable", err, current.Retrieval)
	}
}

func TestRecoveryRetrievalRespectsReadersAndDoesNotTrustStoredPresence(t *testing.T) {
	var requests atomic.Int32
	b, owner := recoveryTransferBackup(t, func(http.ResponseWriter, *http.Request) { requests.Add(1) })
	job, path, content := retrievableFixture(t, b)
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	reader, _, err := b.OpenRecoveryBackup(t.Context(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.RetrieveRecoveryBackup(t.Context(), contract.RecoveryRetrieveRequest{ID: job.ID, ConfirmDownload: true, ConfirmReplace: true}); !errors.Is(err, contract.ErrBusy) {
		t.Fatal("retrieval replaced active reader", err)
	}
	_ = reader.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	job.LocalState = "present"
	if err := owner.SaveRecoveryJob(t.Context(), job, job.State); err != nil {
		t.Fatal(err)
	}
	status, err := b.RecoveryBackups(t.Context())
	if err != nil || status.Items[0].LocalState != "missing" || requests.Load() != 0 {
		t.Fatal("history trusted stale presence or downloaded automatically", err, status)
	}
}

func TestRecoveryInterruptedRetrievalRemovesOnlyOwnedStaging(t *testing.T) {
	b, owner := recoveryTransferBackup(t, func(http.ResponseWriter, *http.Request) { t.Error("startup retried network transfer") })
	job, path, content := retrievableFixture(t, b)
	job.Retrieval = "running"
	if err := owner.SaveRecoveryJob(t.Context(), job, job.State); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".download", []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(filepath.Dir(path), "unrelated.download")
	if err := os.WriteFile(unrelated, []byte("unowned"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := b.recoverInterruptedBackups(t.Context()); err != nil {
		t.Fatal(err)
	}
	current, err := owner.RecoveryJob(t.Context(), job.ID)
	if err != nil || current.Retrieval != "interrupted" || current.State != "verified" {
		t.Fatal("interrupted retrieval not preserved", err, current)
	}
	if _, err := os.Stat(path + ".download"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("partial retained", err)
	}
	if actual, err := os.ReadFile(path); err != nil || !bytes.Equal(actual, content) {
		t.Fatal("published archive removed", err)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatal("unowned file removed", err)
	}
}

func TestRecoveryRetrievalRefusesAliasesAndUntrustedTLS(t *testing.T) {
	b, owner := recoveryTransferBackup(t, func(http.ResponseWriter, *http.Request) { t.Error("alias used network") })
	job, path, _ := retrievableFixture(t, b)
	outside := filepath.Join(t.TempDir(), "outside.yhb")
	if err := os.WriteFile(outside, []byte("preserved"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if _, err := b.RetrieveRecoveryBackup(t.Context(), contract.RecoveryRetrieveRequest{ID: job.ID, ConfirmDownload: true, ConfirmReplace: true}); err == nil {
		t.Fatal("followed archive alias")
	}
	_ = os.Remove(path)
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("untrusted TLS accepted") }))
	defer server.Close()
	options, _ := owner.Get(t.Context())
	options.S3.EndpointURL = server.URL
	if err := owner.Save(t.Context(), options); err != nil {
		t.Fatal(err)
	}
	job.S3Digest, _ = recoveryS3Digest(options.S3)
	if err := owner.SaveRecoveryJob(t.Context(), job, job.State); err != nil {
		t.Fatal(err)
	}
	if _, err := b.RetrieveRecoveryBackup(t.Context(), contract.RecoveryRetrieveRequest{ID: job.ID, ConfirmDownload: true}); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
}

func TestRecoveryRetrievalWriterBudgetSpaceAndCancellation(t *testing.T) {
	var destination bytes.Buffer
	writer := recoveryRetrievalWriter{ctx: t.Context(), output: &destination, directory: t.TempDir(), remaining: 2}
	if _, err := writer.Write([]byte("too big")); err == nil || destination.Len() != 0 {
		t.Fatal("byte budget bypassed")
	}
	writer.directory = filepath.Join(t.TempDir(), "missing")
	if _, err := writer.Write([]byte("ok")); err == nil || destination.Len() != 0 {
		t.Fatal("unknown disk capacity bypassed")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	writer.ctx = ctx
	if _, err := writer.Write([]byte("ok")); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled writer continued", err)
	}
	if _, err := io.Copy(&writer, strings.NewReader("ok")); err == nil {
		t.Fatal("copy ignored cancellation")
	}
}

func TestRecoveryRetrievalThenAuthenticatesRealDeploymentInventory(t *testing.T) {
	source, key := testfixture.BasicDeployment(t)
	archive := filepath.Join(t.TempDir(), "source.yhb")
	manifest, err := recovery.Create(t.Context(), source, archive, backuparchive.Encryption{Recipient: key.Recipient().String()}, recovery.CreateOptions{ConfirmedMaintenance: true})
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	b, owner := recoveryTransferBackup(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(content) })
	job, path, _ := retrievableFixture(t, b)
	hash := sha256.Sum256(content)
	job.Size, job.SHA256 = int64(len(content)), hex.EncodeToString(hash[:])
	job.BackupID, job.InstanceID = manifest.ID, manifest.InstanceID
	job.ObjectKey = "recovery/" + job.InstanceID + "/" + job.BackupID + ".yhb"
	if err := owner.SaveRecoveryJob(t.Context(), job, job.State); err != nil {
		t.Fatal(err)
	}
	if _, err := b.RetrieveRecoveryBackup(t.Context(), contract.RecoveryRetrieveRequest{ID: job.ID, ConfirmDownload: true}); err != nil {
		t.Fatal(err)
	}
	verified, err := b.VerifyRecoveryBackup(t.Context(), contract.RecoveryVerifyRequest{ID: job.ID, Identity: key.String()})
	if err != nil || !verified.CompleteInventory || verified.ID != manifest.ID {
		t.Fatal("retrieved deployment archive did not authenticate", err)
	}
	file, _, err := b.OpenRecoveryBackup(t.Context(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	actual, err := io.ReadAll(file)
	if err != nil || !bytes.Equal(actual, content) {
		t.Fatal("download after retrieval differs", err)
	}
	if _, err := os.Stat(path + ".download"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("retrieval staging retained", err)
	}
}
