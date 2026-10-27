package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
	"uuid"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/s3"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
)

func recoveryS3Digest(options contract.S3) (string, error) {
	data, err := json.Marshal(options)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func (b *Backup) CreateRecoveryBackup(ctx context.Context, request contract.RecoveryBackupRequest) (contract.RecoveryBackup, error) {
	if b.store == nil {
		return contract.RecoveryBackup{}, errors.New("backup store is unavailable")
	}
	if !request.ConfirmMaintenance {
		return contract.RecoveryBackup{}, errors.New("full backup requires explicit confirmation of temporary service interruption")
	}
	if !b.mu.TryLock() {
		return contract.RecoveryBackup{}, errBackupBusy
	}
	defer func() { b.mu.Unlock(); b.refreshBackupMetrics(ctx) }()
	if b.maintainer == nil {
		return contract.RecoveryBackup{}, errors.New("service maintenance is unavailable; use the offline recovery CLI")
	}
	if supported, reason := b.maintainer.Supported(); !supported {
		return contract.RecoveryBackup{}, errors.New(reason)
	}
	options, err := b.store.Get(ctx)
	if err != nil {
		return contract.RecoveryBackup{}, err
	}
	if options.Recovery == nil {
		return contract.RecoveryBackup{}, errors.New("configure full backup encryption first")
	}
	policy, err := backupstore.NormalizeRecoveryPolicy(*options.Recovery)
	if err != nil {
		return contract.RecoveryBackup{}, err
	}
	if policy.Recipient == "" || !policy.AllowMaintenance {
		return contract.RecoveryBackup{}, errors.New("full backup requires a public recipient and maintenance consent")
	}
	if policy.Target == "s3" && !options.S3.Enabled {
		return contract.RecoveryBackup{}, errors.New("full S3 backup requires enabled S3 settings")
	}
	digest, err := recoveryS3Digest(options.S3)
	if err != nil {
		return contract.RecoveryBackup{}, err
	}
	job := backupstore.RecoveryJob{
		ID: uuid.New().String(), CreatedAt: time.Now().UTC(), Target: policy.Target, State: "queued", IncludesHistory: policy.IncludeHistory, Policy: policy, S3Digest: digest}
	if err := b.store.EnqueueRecovery(ctx, job); err != nil {
		return contract.RecoveryBackup{}, err
	}
	if err := b.maintainer.StartRecovery(ctx, job.ID, time.Duration(policy.TimeoutMinutes)*time.Minute); err != nil {
		job.State, job.ErrorCode, job.CompletedAt = "failed", "maintenance_start_failed", time.Now().UTC()
		// Never include manager/provider output or secret-bearing errors in the
		// durable API record. Preserve the original error only to the caller.
		_ = b.store.SaveRecoveryJob(context.WithoutCancel(ctx), job, "queued")
		return contract.RecoveryBackup{}, err
	}
	return job.RecoveryBackup, nil
}

// resumeRecoveryBackups runs on the existing schedule owner, never an additional
// worker/ticker. Uploads happen after restart through b.proxy and share b.mu with
// legacy/manual backup work. Interrupting a transfer retains the private archive.
func (b *Backup) resumeRecoveryBackups(ctx context.Context) error {
	items, err := b.store.RecoveryPending(ctx)
	if err != nil {
		return err
	}
	// An empty or externally owned capture queue must not contend with manual
	// configuration backups. Only transfer/deletion work needs the shared lease.
	actionable := false
	for _, item := range items {
		if item.State == "deleting" || (item.State == "local_ready" && item.Target == "s3") {
			actionable = true
			break
		}
	}
	if !actionable {
		return nil
	}
	if !b.mu.TryLock() {
		return errBackupBusy
	}
	defer b.mu.Unlock()
	var combined error
	for _, item := range items {
		if err := ctx.Err(); err != nil {
			return errors.Join(combined, err)
		}
		if item.State == "deleting" {
			job, err := b.store.RecoveryJob(ctx, item.ID)
			if err != nil {
				combined = errors.Join(combined, err)
				continue
			}
			if job.State != "deleting" {
				continue
			}
			if err := b.deleteRecoveryBackup(ctx, job); err != nil {
				combined = errors.Join(combined, err)
			}
			continue
		}
		if item.State != "local_ready" || item.Target != "s3" {
			continue
		}
		job, err := b.store.RecoveryJob(ctx, item.ID)
		if err != nil {
			combined = errors.Join(combined, err)
			continue
		}
		if job.State != "local_ready" || job.Target != "s3" {
			continue
		}
		if err := b.uploadRecoveryBackup(ctx, job); err != nil {
			combined = errors.Join(combined, err)
		}
	}
	return combined
}

func (b *Backup) uploadRecoveryBackup(ctx context.Context, job backupstore.RecoveryJob) (resultErr error) {
	policy, err := backupstore.NormalizeRecoveryPolicy(job.Policy)
	if err != nil {
		return err
	}
	job.Policy = policy
	if err := validateRecoveryObjectKey(job); err != nil {
		return err
	}
	options, err := b.store.Get(ctx)
	if err != nil {
		return err
	}
	digest, err := recoveryS3Digest(options.S3)
	if err != nil {
		return err
	}
	if digest != job.S3Digest || !options.S3.Enabled {
		job.State, job.ErrorCode = "failed", "destination_changed"
		return b.store.SaveRecoveryJob(ctx, job, "local_ready")
	}
	path, err := recoveryArchivePath(b.dir, job.ID)
	if err != nil {
		return err
	}
	size, hash, err := digestRecoveryArchive(ctx, path)
	if err != nil || size != job.Size || hash != job.SHA256 {
		job.State, job.ErrorCode = "failed", "local_archive_changed"
		return b.store.SaveRecoveryJob(ctx, job, "local_ready")
	}
	if job.UploadAttempts >= 3 {
		job.State, job.ErrorCode = "failed", "upload_attempt_limit"
		return b.store.SaveRecoveryJob(ctx, job, "local_ready")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(job.Policy.TimeoutMinutes)*time.Minute)
	defer cancel()
	job.State, job.UploadAttempts = "uploading", job.UploadAttempts+1
	if err := b.store.SaveRecoveryJob(ctx, job, "local_ready"); err != nil {
		return err
	}
	failureCode := "upload_failed"
	defer func() {
		if resultErr != nil {
			state := "failed"
			if ctx.Err() != nil {
				state = "local_ready"
			}
			job.State, job.ErrorCode = state, failureCode
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			_ = b.store.SaveRecoveryJob(cleanup, job, "uploading")
		}
	}()
	client, err := s3.NewS3(options.S3, b.proxy)
	if err != nil {
		return err
	}
	defer client.Close()
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := client.PutReader(ctx, file, size, job.ObjectKey); err != nil {
		return err
	}
	failureCode = "readback_failed"
	readback := sha256.New()
	count, err := client.Download(ctx, readback, job.ObjectKey, size)
	if err != nil {
		return err
	}
	if count != size || hex.EncodeToString(readback.Sum(nil)) != job.SHA256 {
		failureCode = "verification_failed"
		return errors.New("uploaded encrypted archive failed readback verification")
	}
	job.State, job.ErrorCode, job.Verification = "verified", "", "s3_ciphertext_readback"
	job.CompletedAt = time.Now().UTC()
	return b.store.SaveRecoveryJob(ctx, job, "uploading")
}

func (b *Backup) OpenRecoveryBackup(ctx context.Context, id string) (io.ReadSeekCloser, contract.RecoveryBackup, error) {
	if b.store == nil {
		return nil, contract.RecoveryBackup{}, errors.New("backup store is unavailable")
	}
	if !b.mu.TryLock() {
		return nil, contract.RecoveryBackup{}, errBackupBusy
	}
	defer b.mu.Unlock()
	if b.activeRecoveryDownloads.Load() >= 4 {
		return nil, contract.RecoveryBackup{}, errBackupBusy
	}
	job, err := b.store.RecoveryJob(ctx, id)
	if err != nil {
		return nil, contract.RecoveryBackup{}, err
	}
	if job.State != "local_ready" && job.State != "verified" {
		return nil, contract.RecoveryBackup{}, errors.New("backup is not ready for download")
	}
	file, err := openManagedRecoveryArchive(b.dir, id)
	if err != nil {
		return nil, contract.RecoveryBackup{}, err
	}
	if b.recoveryReaders == nil {
		b.recoveryReaders = make(map[string]int)
	}
	b.recoveryReaders[id]++
	b.activeRecoveryDownloads.Add(1)
	lease := &recoveryArchiveReader{File: file, release: func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.recoveryReaders[id]--
		b.activeRecoveryDownloads.Add(-1)
		if b.recoveryReaders[id] == 0 {
			delete(b.recoveryReaders, id)
		}
	}}
	return lease, job.RecoveryBackup, nil
}

type recoveryArchiveReader struct {
	*os.File
	once    sync.Once
	release func()
}

func (r *recoveryArchiveReader) Close() error {
	var err error
	r.once.Do(func() { err = r.File.Close(); r.release() })
	return err
}

// A restarted runtime cannot own the previous process's in-flight operation.
// Captures are never adopted without their completed authenticated publication;
// interrupted uploads restart from the unchanged encrypted local archive.
func (b *Backup) recoverInterruptedBackups(ctx context.Context) error {
	items, err := b.store.RecoveryPending(ctx)
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.State == "local_ready" || item.State == "deleting" {
			continue
		}
		job, err := b.store.RecoveryJob(ctx, item.ID)
		if err != nil {
			return err
		}
		expected := job.State
		if expected == "uploading" {
			job.State, job.ErrorCode = "local_ready", "upload_interrupted"
		} else {
			job.State, job.ErrorCode, job.CompletedAt = "failed", "capture_interrupted", time.Now().UTC()
		}
		if err := b.store.SaveRecoveryJob(ctx, job, expected); err != nil {
			return err
		}
	}
	return nil
}

func validateRecoveryObjectKey(job backupstore.RecoveryJob) error {
	for _, id := range []string{job.BackupID, job.InstanceID} {
		value, err := uuid.Parse(id)
		if err != nil || value == (uuid.UUID{}) || value.String() != id {
			return errors.New("invalid encrypted backup identity")
		}
	}
	if job.ObjectKey != "recovery/"+job.InstanceID+"/"+job.BackupID+".yhb" {
		return errors.New("backup object key does not match its owned namespace")
	}
	return nil
}

func (b *Backup) RetryRecoveryBackup(ctx context.Context, id string) error {
	if b.store == nil {
		return errors.New("backup store is unavailable")
	}
	if !b.mu.TryLock() {
		return errBackupBusy
	}
	defer func() { b.mu.Unlock(); b.refreshBackupMetrics(ctx); b.reschedule() }()
	job, err := b.store.RecoveryJob(ctx, id)
	if err != nil {
		return err
	}
	if job.State != "failed" || job.Target != "s3" || job.BackupID == "" {
		return errors.New("only failed uploads of completed encrypted archives can be retried")
	}
	job.State, job.ErrorCode, job.UploadAttempts = "local_ready", "", 0
	return b.store.SaveRecoveryJob(ctx, job, "failed")
}

func openManagedRecoveryArchive(directory, id string) (*os.File, error) {
	path, err := recoveryArchivePath(directory, id)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	relative, err := filepath.Rel(directory, path)
	if err != nil {
		return nil, err
	}
	if present, err := recoveryDestination(root, relative, false); err != nil || !present {
		return nil, errors.New("managed archive is unavailable")
	}
	file, err := root.Open(relative)
	if err != nil {
		return nil, err
	}
	return file, nil
}
