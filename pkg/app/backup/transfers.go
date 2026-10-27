package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	backupfs "github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/backupfs"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/s3"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
)

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
	path, err := backupfs.ArchivePath(b.dir, job.ID)
	if err != nil {
		return err
	}
	size, hash, err := backupfs.DigestArchive(ctx, path)
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
func openManagedRecoveryArchive(directory, id string) (*os.File, error) {
	path, err := backupfs.ArchivePath(directory, id)
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
	if present, err := backupfs.Destination(root, relative, false); err != nil {
		return nil, err
	} else if !present {
		return nil, os.ErrNotExist
	}
	file, err := root.Open(relative)
	if err != nil {
		return nil, err
	}
	return file, nil
}
