package recovery

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	backupfs "github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/backupfs"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	backuparchive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

// RecoveryService controls the existing installed service; tests close real
// database owners at this seam rather than pretending a live copy is coherent.
type Service interface {
	Stop(context.Context) error
	Start(context.Context) error
}

func acquireRecoveryCaptureLease(ctx context.Context, directory string) (*os.File, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		lease, err := lockfile.Acquire(filepath.Join(directory, ".recovery-maintenance.lock"))
		if err == nil || !errors.Is(err, syscall.EWOULDBLOCK) {
			return lease, err
		}
		// The previous helper can still be unwinding after the restarted API
		// becomes reachable. Wait briefly without stopping any live owners.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// RestartService is the independent host's crash fallback. It must take
// the same lease as capture/update before starting the server: an unconditional
// service-manager ExecStopPost could otherwise restart SQLite during a binary
// swap owned by an update helper. A competing owner retains restart responsibility.
func RestartService(ctx context.Context, directory, id string, service Service) error {
	if service == nil {
		return errors.New("installed service coordinator is unavailable")
	}
	directory, err := backupfs.CanonicalDirectory(directory)
	if err != nil {
		return err
	}
	if _, err := backupfs.ArchivePath(directory, id); err != nil {
		return err
	}
	operation, err := lockfile.Acquire(filepath.Join(directory, ".recovery-maintenance.lock"))
	if err != nil {
		return err
	}
	defer operation.Close()
	var job backupstore.RecoveryJob
	if err := withRecoveryJobStore(ctx, directory, func(owner *backupstore.Store) error {
		var err error
		job, err = owner.RecoveryJob(ctx, id)
		return err
	}); err != nil {
		return err
	}
	if job.ErrorCode == "maintenance_busy" {
		return nil
	}
	return service.Start(ctx)
}

func withOfflineBackupStore(ctx context.Context, directory string, fn func(*backupstore.Store) error) error {
	lifecycle, err := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
	if err != nil {
		return err
	}
	defer lifecycle.Close()
	if err := requireRecoveryLifecycle(directory, lifecycle); err != nil {
		return err
	}
	if err := GuardMaintenance(directory); err != nil {
		return err
	}
	db, err := sqlite.Open(ctx, filepath.Join(directory, "state.db"))
	if err != nil {
		return err
	}
	defer db.Close()
	return fn(backupstore.New(db.DB()))
}

// withRecoveryJobStore performs metadata-only SQL updates without bootstrapping
// or migrating a store. It is also safe when a failed service stop leaves the
// server online: SQLite coordinates that ordinary history write. Handles always
// close before the collector checks stopped database owners.
func withRecoveryJobStore(ctx context.Context, directory string, fn func(*backupstore.Store) error) error {
	uri := &url.URL{Scheme: "file", Path: filepath.ToSlash(filepath.Join(directory, "state.db")), RawQuery: "mode=rw"}
	if filepath.VolumeName(directory) != "" && !strings.HasPrefix(uri.Path, "/") {
		uri.Path = "/" + uri.Path
	}
	db, err := sql.Open(sqlite.DriverName(), uri.String())
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, "PRAGMA busy_timeout=5000; PRAGMA trusted_schema=OFF"); err != nil {
		return err
	}
	return fn(backupstore.New(db))
}

// Capture coordinates one immutable queued request. The existing
// offline collector remains responsible for inventory, SQLite snapshots and
// encryption. Uploading waits until the ordinary runtime/proxy is back online.
func Capture(ctx context.Context, directory, id string, service Service) (resultErr error) {
	if service == nil {
		return errors.New("installed service coordinator is unavailable")
	}
	directory, err := backupfs.CanonicalDirectory(directory)
	if err != nil {
		return err
	}
	archive, err := backupfs.ArchivePath(directory, id)
	if err != nil {
		return err
	}
	operation, err := acquireRecoveryCaptureLease(ctx, directory)
	if err != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = withRecoveryJobStore(cleanup, directory, func(owner *backupstore.Store) error {
			job, err := owner.RecoveryJob(cleanup, id)
			if err != nil {
				return err
			}
			job.State, job.ErrorCode, job.CompletedAt = "failed", "maintenance_busy", time.Now().UTC()
			return owner.SaveRecoveryJob(cleanup, job, "queued")
		})
		return err
	}
	defer operation.Close()
	defer func() {
		restart, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer cancel()
		restartErr := service.Start(restart)
		resultErr = errors.Join(resultErr, restartErr)
		if restartErr != nil {
			_ = withRecoveryJobStore(restart, directory, func(owner *backupstore.Store) error {
				job, err := owner.RecoveryJob(restart, id)
				if err != nil {
					return err
				}
				expected := job.State
				job.ErrorCode = "service_restart_failed"
				return owner.SaveRecoveryJob(restart, job, expected)
			})
		}
	}()
	defer func() {
		if resultErr == nil {
			return
		}
		failed, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = withRecoveryJobStore(failed, directory, func(owner *backupstore.Store) error {
			current, err := owner.RecoveryJob(failed, id)
			if err != nil {
				return err
			}
			if current.State != "queued" && current.State != "capturing" {
				return nil
			}
			expected := current.State
			current.State, current.ErrorCode, current.CompletedAt = "failed", "capture_failed", time.Now().UTC()
			return owner.SaveRecoveryJob(failed, current, expected)
		})
	}()
	if err := service.Stop(ctx); err != nil {
		return err
	}
	var job backupstore.RecoveryJob
	if err := withOfflineBackupStore(ctx, directory, func(owner *backupstore.Store) error {
		var err error
		job, err = owner.RecoveryJob(ctx, id)
		if err != nil {
			return err
		}
		if job.State != "queued" {
			return errors.New("backup request is no longer queued")
		}
		policy, err := backupstore.NormalizeRecoveryPolicy(job.Policy)
		if err != nil || policy.Recipient == "" || !policy.AllowMaintenance || policy.Target != job.Target {
			return errors.New("backup request lacks a validated recipient or maintenance consent")
		}
		job.Policy, job.State = policy, "capturing"
		return owner.SaveRecoveryJob(ctx, job, "queued")
	}); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(job.Policy.TimeoutMinutes)*time.Minute)
	defer cancel()
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(directory, archive)
	if err != nil {
		_ = root.Close()
		return err
	}
	present, destinationErr := backupfs.Destination(root, relative, true)
	_ = root.Close()
	if destinationErr != nil {
		return destinationErr
	}
	if present {
		return errors.New("managed backup destination already exists")
	}
	// A pre-existing managed archive is never overwritten or adopted following
	// a helper crash. It remains available for an explicit offline verification.
	manifest, err := Create(ctx, directory, archive, backuparchive.Encryption{Recipient: job.Policy.Recipient}, CreateOptions{ConfirmedMaintenance: true, IncludeHistory: job.Policy.IncludeHistory})
	if err != nil {
		return err
	}
	job.Size, job.SHA256, err = backupfs.DigestArchive(ctx, archive)
	if err != nil {
		return err
	}
	job.BackupID, job.InstanceID = manifest.ID, manifest.InstanceID
	job.State, job.Verification, job.CompletedAt = "local_ready", "ciphertext_sha256", time.Now().UTC()
	job.ObjectKey = "recovery/" + manifest.InstanceID + "/" + manifest.ID + ".yhb"
	return withOfflineBackupStore(ctx, directory, func(owner *backupstore.Store) error {
		return owner.SaveRecoveryJob(ctx, job, "capturing")
	})
}
