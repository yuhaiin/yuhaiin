package app

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"uuid"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/s3"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

// RecoveryMaintainer is supplied by the installed-service host. It launches an
// independent helper; stopping the server must not cancel its own snapshot job.
type RecoveryMaintainer interface {
	Supported() (bool, string)
	StartRecovery(context.Context, string, time.Duration) error
}

// RecoveryService controls the existing installed service; tests close real
// database owners at this seam rather than pretending a live copy is coherent.
type RecoveryService interface {
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

// RestartRecoveryService is the independent host's crash fallback. It must take
// the same lease as capture/update before starting the server: an unconditional
// service-manager ExecStopPost could otherwise restart SQLite during a binary
// swap owned by an update helper. A competing owner retains restart responsibility.
func RestartRecoveryService(ctx context.Context, directory, id string, service RecoveryService) error {
	if service == nil {
		return errors.New("installed service coordinator is unavailable")
	}
	directory, err := canonicalRecoveryDirectory(directory)
	if err != nil {
		return err
	}
	if _, err := recoveryArchivePath(directory, id); err != nil {
		return err
	}
	operation, err := lockfile.Acquire(filepath.Join(directory, ".recovery-maintenance.lock"))
	if err != nil {
		return err
	}
	defer operation.Close()
	var job store.RecoveryJob
	if err := withRecoveryJobStore(ctx, directory, func(owner *store.BackupStore) error {
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

func recoveryArchivePath(directory, id string) (string, error) {
	value, err := uuid.Parse(id)
	if err != nil || value == (uuid.UUID{}) || value.String() != id {
		return "", errors.New("invalid backup identifier")
	}
	return filepath.Join(directory, ".recovery-archives", id+".yhb"), nil
}

func withOfflineBackupStore(ctx context.Context, directory string, fn func(*store.BackupStore) error) error {
	lifecycle, err := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
	if err != nil {
		return err
	}
	defer lifecycle.Close()
	if err := requireRecoveryLifecycle(directory, lifecycle); err != nil {
		return err
	}
	if err := GuardRecoveryMaintenance(directory); err != nil {
		return err
	}
	db, err := sqlite.Open(ctx, filepath.Join(directory, "state.db"))
	if err != nil {
		return err
	}
	defer db.Close()
	return fn(store.NewBackupStore(db.DB()))
}

// withRecoveryJobStore performs metadata-only SQL updates without bootstrapping
// or migrating a store. It is also safe when a failed service stop leaves the
// server online: SQLite coordinates that ordinary history write. Handles always
// close before the collector checks stopped database owners.
func withRecoveryJobStore(ctx context.Context, directory string, fn func(*store.BackupStore) error) error {
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
	return fn(store.NewBackupStore(db))
}

// RunRecoveryCapture coordinates one immutable queued request. The existing
// offline collector remains responsible for inventory, SQLite snapshots and
// encryption. Uploading waits until the ordinary runtime/proxy is back online.
func RunRecoveryCapture(ctx context.Context, directory, id string, service RecoveryService) (resultErr error) {
	if service == nil {
		return errors.New("installed service coordinator is unavailable")
	}
	directory, err := canonicalRecoveryDirectory(directory)
	if err != nil {
		return err
	}
	archive, err := recoveryArchivePath(directory, id)
	if err != nil {
		return err
	}
	operation, err := acquireRecoveryCaptureLease(ctx, directory)
	if err != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = withRecoveryJobStore(cleanup, directory, func(owner *store.BackupStore) error {
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
			_ = withRecoveryJobStore(restart, directory, func(owner *store.BackupStore) error {
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
		_ = withRecoveryJobStore(failed, directory, func(owner *store.BackupStore) error {
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
	var job store.RecoveryJob
	if err := withOfflineBackupStore(ctx, directory, func(owner *store.BackupStore) error {
		var err error
		job, err = owner.RecoveryJob(ctx, id)
		if err != nil {
			return err
		}
		if job.State != "queued" {
			return errors.New("backup request is no longer queued")
		}
		policy, err := store.NormalizeRecoveryPolicy(job.Policy)
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
	present, destinationErr := recoveryDestination(root, relative, true)
	_ = root.Close()
	if destinationErr != nil {
		return destinationErr
	}
	if present {
		return errors.New("managed backup destination already exists")
	}
	// A pre-existing managed archive is never overwritten or adopted following
	// a helper crash. It remains available for an explicit offline verification.
	manifest, err := CreateOfflineRecovery(ctx, directory, archive, store.RecoveryEncryption{Recipient: job.Policy.Recipient}, RecoveryCreateOptions{ConfirmedMaintenance: true, IncludeHistory: job.Policy.IncludeHistory})
	if err != nil {
		return err
	}
	job.Size, job.SHA256, err = digestRecoveryArchive(ctx, archive)
	if err != nil {
		return err
	}
	job.BackupID, job.InstanceID = manifest.ID, manifest.InstanceID
	job.State, job.Verification, job.CompletedAt = "local_ready", "ciphertext_sha256", time.Now().UTC()
	job.ObjectKey = "recovery/" + manifest.InstanceID + "/" + manifest.ID + ".yhb"
	return withOfflineBackupStore(ctx, directory, func(owner *store.BackupStore) error {
		return owner.SaveRecoveryJob(ctx, job, "capturing")
	})
}

func digestRecoveryArchive(ctx context.Context, path string) (int64, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer file.Close()
	return digestRecoveryArchiveFile(ctx, file)
}

func digestRecoveryArchiveFile(ctx context.Context, file *os.File) (int64, string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return 0, "", err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > s3.MaxObjectBytes {
		return 0, "", errors.New("managed encrypted archive exceeds its 100 GiB limit")
	}
	hash := sha256.New()
	buffer := make([]byte, 32<<10)
	var count int64
	for {
		if err := ctx.Err(); err != nil {
			return 0, "", err
		}
		n, err := file.Read(buffer)
		if n > 0 {
			count += int64(n)
			if count > info.Size() {
				return 0, "", errors.New("encrypted archive grew during verification")
			}
			_, _ = hash.Write(buffer[:n])
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, "", err
		}
	}
	after, err := file.Stat()
	if err != nil || count != info.Size() || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return 0, "", errors.New("encrypted archive changed during verification")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return 0, "", err
	}
	return count, hex.EncodeToString(hash.Sum(nil)), nil
}

func (b *Backup) RecoveryBackups(ctx context.Context) (contract.RecoveryBackupStatus, error) {
	out := contract.RecoveryBackupStatus{Items: []contract.RecoveryBackup{}}
	if b.store == nil {
		return out, errors.New("backup store is unavailable")
	}
	if b.instance != nil && b.instance.RecoveryMaintenance != nil {
		out.Supported, out.Reason = b.instance.RecoveryMaintenance.Supported()
	} else {
		out.Reason = "full backup maintenance requires an installed service; use the offline recovery CLI"
	}
	version := b.metricsVersion.Add(1)
	var err error
	out.Items, err = b.store.RecoveryHistory(ctx)
	if err == nil {
		b.compileBackupMetrics(version, out.Items)
	}
	return out, err
}
