package backup

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"uuid"

	"filippo.io/age"
	backupfs "github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/backupfs"
	testfixture "github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/testfixture"
	recovery "github.com/Asutorufa/yuhaiin/pkg/app/backup/recovery"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	backuparchive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

type recoveryMaintainerTest struct {
	id   string
	fail bool
}

func (*recoveryMaintainerTest) Supported() (bool, string) { return true, "" }
func (m *recoveryMaintainerTest) StartRecovery(_ context.Context, id string, _ time.Duration) error {
	m.id = id
	if m.fail {
		return errors.New("fixture manager unavailable")
	}
	return nil
}

type recoveryServiceTest struct{ stop, start func(context.Context) error }

func (s recoveryServiceTest) Stop(ctx context.Context) error  { return s.stop(ctx) }
func (s recoveryServiceTest) Start(ctx context.Context) error { return s.start(ctx) }

func TestManagedRecoveryCaptureCoordinatesRealOwnersAndPrivateArchive(t *testing.T) {
	for _, fault := range []string{"none", "stop", "cancel", "existing-archive", "restart"} {
		t.Run(fault, func(t *testing.T) {
			directory, key := testfixture.Deployment(t)
			db, err := testfixture.OpenState(t.Context(), filepath.Join(directory, "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			identity, err := testfixture.OpenManagement(t.Context(), filepath.Join(directory, "management.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer identity.Close()
			lifecycle, err := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
			if err != nil {
				t.Fatal(err)
			}
			defer lifecycle.Close()
			owner := backupstore.New(db.DB())
			config, err := owner.Get(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			config.Recovery = &contractrecovery.Policy{Target: "local", Recipient: key.Recipient().String(), AllowMaintenance: true}
			if err := owner.Save(t.Context(), config); err != nil {
				t.Fatal(err)
			}
			manager := new(recoveryMaintainerTest)
			b := &Backup{store: owner, dir: directory, maintainer: manager}
			if _, err := b.CreateRecoveryBackup(t.Context(), contractrecovery.BackupRequest{}); err == nil {
				t.Fatal("maintenance accepted without confirmation")
			}
			queued, err := b.CreateRecoveryBackup(t.Context(), contractrecovery.BackupRequest{ConfirmMaintenance: true})
			if err != nil {
				t.Fatal(err)
			}
			if queued.ID != manager.id || queued.State != "queued" {
				t.Fatal("maintenance request was not persisted before launch")
			}
			if _, err := b.CreateRecoveryBackup(t.Context(), contractrecovery.BackupRequest{ConfirmMaintenance: true}); err == nil {
				t.Fatal("concurrent full captures accepted")
			}
			archive, _ := backupfs.ArchivePath(directory, queued.ID)
			if fault == "existing-archive" {
				if err := os.MkdirAll(filepath.Dir(archive), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(archive, []byte("existing protected file"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			started := false
			service := recoveryServiceTest{
				stop: func(context.Context) error {
					if fault == "stop" {
						return errors.New("fixture stop failure")
					}
					if err := errors.Join(db.Close(), identity.Close(), lifecycle.Close()); err != nil {
						return err
					}
					if fault == "cancel" {
						cancel()
					}
					return nil
				},
				start: func(ctx context.Context) error {
					started = true
					if ctx.Err() != nil {
						t.Fatal("cleanup inherited cancelled backup context")
					}
					if fault == "restart" {
						return errors.New("fixture restart failure")
					}
					opened, err := sqlite.Open(ctx, filepath.Join(directory, "state.db"))
					if err != nil {
						return err
					}
					defer opened.Close()
					auth, err := sqlite.OpenManagement(ctx, filepath.Join(directory, "management.db"))
					if err != nil {
						return err
					}
					defer auth.Close()
					var users int
					if err := auth.DB().QueryRowContext(ctx, "SELECT count(*) FROM management_users WHERE id='owner'").Scan(&users); err != nil {
						return err
					}
					if users != 1 {
						t.Fatal("capture changed management identity")
					}
					return nil
				},
			}
			err = recovery.Capture(ctx, directory, queued.ID, service)
			if (fault == "none") != (err == nil) {
				t.Fatalf("capture result: fault=%s err=%v", fault, err)
			}
			if !started {
				t.Fatal("service restart was not attempted")
			}
			recorded, err := testfixture.OpenState(t.Context(), filepath.Join(directory, "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			result, readErr := backupstore.New(recorded.DB()).RecoveryJob(t.Context(), queued.ID)
			if err := errors.Join(readErr, recorded.Close()); err != nil {
				t.Fatal(err)
			}
			if fault == "none" || fault == "restart" {
				if result.State != "local_ready" || result.Size < 1 || result.SHA256 == "" {
					t.Fatal("complete archive not recorded", result.State)
				}
				if fault == "restart" && result.ErrorCode != "service_restart_failed" {
					t.Fatal("restart failure hidden")
				}
				input, err := os.Open(archive)
				if err != nil {
					t.Fatal(err)
				}
				defer input.Close()
				prepared, err := backuparchive.Prepare(t.Context(), input, t.TempDir(), backuparchive.Decryption{Identity: key.String()})
				if err != nil {
					t.Fatal(err)
				}
				defer prepared.Close()
				if !prepared.Manifest.CompleteInventory || prepared.Manifest.ID != result.BackupID {
					t.Fatal("recorded archive does not match authenticated inventory")
				}
			} else if result.State != "failed" {
				t.Fatal("failed capture remained pending", result.State)
			}
			if fault == "existing-archive" {
				original, err := os.ReadFile(archive)
				if err != nil || string(original) != "existing protected file" {
					t.Fatal("overwrote existing managed archive", err)
				}
			}
		})
	}
}

func TestManagedRecoveryVerificationDoesNotPersistDecryptionMaterial(t *testing.T) {
	directory, key := testfixture.Deployment(t)
	db, err := testfixture.OpenState(t.Context(), filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	owner := backupstore.New(db.DB())
	config, err := owner.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	config.Recovery = &contractrecovery.Policy{Target: "local", Recipient: key.Recipient().String(), AllowMaintenance: true}
	if err := owner.Save(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	manager := new(recoveryMaintainerTest)
	b := &Backup{store: owner, dir: directory, maintainer: manager}
	queued, err := b.CreateRecoveryBackup(t.Context(), contractrecovery.BackupRequest{ConfirmMaintenance: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := recovery.Capture(t.Context(), directory, queued.ID, recoveryServiceTest{stop: func(context.Context) error { return nil }, start: func(context.Context) error { return nil }}); err != nil {
		t.Fatal(err)
	}
	db, err = testfixture.OpenState(t.Context(), filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	b.store = backupstore.New(db.DB())
	manifest, err := b.VerifyRecoveryBackup(t.Context(), contractrecovery.VerifyRequest{ID: queued.ID, Identity: key.String()})
	if err != nil {
		t.Fatal(err)
	}
	if !manifest.CompleteInventory {
		t.Fatal("verification did not check deployment inventory")
	}
	wrong, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.VerifyRecoveryBackup(t.Context(), contractrecovery.VerifyRequest{ID: queued.ID, Identity: wrong.String()}); err == nil || strings.Contains(err.Error(), wrong.String()) {
		t.Fatal("wrong key accepted or exposed in error")
	}
	var persisted string
	if err := db.DB().QueryRowContext(t.Context(), "SELECT data_json FROM backup_recovery_history WHERE id=?", queued.ID).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(persisted, key.String()) || strings.Contains(persisted, wrong.String()) {
		t.Fatal("private identity persisted in backup history")
	}
	current, err := b.store.RecoveryJob(t.Context(), queued.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.ArchiveCheck != "failed" || current.ArchiveCheckedAt.IsZero() {
		t.Fatal("last archive check result not saved")
	}
	path, _ := backupfs.ArchivePath(directory, queued.ID)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("tampered")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.VerifyRecoveryBackup(t.Context(), contractrecovery.VerifyRequest{ID: queued.ID, Identity: key.String()}); err == nil {
		t.Fatal("changed ciphertext accepted")
	}
}

func TestRecoveryCrashRestartRespectsConcurrentMaintenanceAndJobOwnership(t *testing.T) {
	b, _ := recoveryTransferBackup(t, func(http.ResponseWriter, *http.Request) { t.Error("restart used network") })
	job := queuedArchiveFixture(t, b, "local", time.Now())
	starts := 0
	service := recoveryServiceTest{
		stop:  func(context.Context) error { t.Fatal("restart fallback stopped the service"); return nil },
		start: func(context.Context) error { starts++; return nil },
	}
	lock, err := lockfile.Acquire(filepath.Join(b.dir, ".recovery-maintenance.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := recovery.RestartService(t.Context(), b.dir, job.ID, service); err == nil || starts != 0 {
		t.Fatal("crash fallback started service during another maintenance operation", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := recovery.RestartService(t.Context(), b.dir, uuid.New().String(), service); err == nil || starts != 0 {
		t.Fatal("unknown backup restarted the service", err)
	}
	if err := recovery.RestartService(t.Context(), b.dir, job.ID, service); err != nil || starts != 1 {
		t.Fatal("crash fallback did not restart the service", err)
	}
	job.State, job.ErrorCode = "failed", "maintenance_busy"
	if err := b.store.SaveRecoveryJob(t.Context(), job, "local_ready"); err != nil {
		t.Fatal(err)
	}
	if err := recovery.RestartService(t.Context(), b.dir, job.ID, service); err != nil || starts != 1 {
		t.Fatal("rejected maintenance restarted an unrelated service owner", err)
	}
}
