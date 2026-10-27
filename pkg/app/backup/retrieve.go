package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	backupfs "github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/backupfs"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/s3"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
)

// FetchArchive retrieves only the recorded object and authenticates its exact
// ciphertext against independently retained metadata. It never decrypts or
// activates a deployment. A complete private temporary file is published only
// after its size and SHA-256 match. The caller owns replacement authorization.
// Offline CLI callers use replace=false; runtime callers hold the backup lease.
func FetchArchive(ctx context.Context, destination string, options contract.S3, expected contract.RecoveryBackup, proxy netapi.Proxy, replace bool) error {
	if expected.Target != "s3" || expected.Size < 1 || expected.Size > s3.MaxObjectBytes || !options.Enabled {
		return errors.New("retrieval requires an enabled S3 destination and a recorded archive size between 1 byte and 100 GiB")
	}
	if err := validateRecoveryObjectKey(backupstore.RecoveryJob{RecoveryBackup: expected}); err != nil {
		return err
	}
	digest, err := hex.DecodeString(expected.SHA256)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != expected.SHA256 {
		return errors.New("retrieval requires the recorded lowercase ciphertext SHA-256")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	parent, name := filepath.Dir(destination), filepath.Base(destination)
	root, err := os.OpenRoot(parent)
	if err != nil {
		return err
	}
	defer root.Close()
	present, err := backupfs.Destination(root, name, false)
	if err != nil {
		return err
	}
	if present && !replace {
		return errors.New("archive destination already exists")
	}
	if err := backupfs.CheckStagingSpace(parent, expected.Size); err != nil {
		return err
	}
	// A deterministic, exclusively created name makes a crash visible. Runtime
	// startup removes it only for a durably recorded interrupted retrieval.
	temporary := name + ".download"
	file, err := root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.New("retrieval staging is unavailable; inspect any interrupted .download file")
	}
	defer func() { _ = file.Close(); _ = root.Remove(temporary) }()
	client, err := s3.NewS3(options, proxy)
	if err != nil {
		return errors.New("invalid S3 retrieval configuration")
	}
	defer client.Close()
	hash := sha256.New()
	output := &recoveryRetrievalWriter{ctx: ctx, output: io.MultiWriter(file, hash), directory: parent, remaining: expected.Size}
	count, err := client.Download(ctx, output, expected.ObjectKey, expected.Size)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Provider errors can contain signed URLs or credential-bearing diagnostics.
		return errors.New("S3 retrieval failed; the existing local archive was preserved")
	}
	if count != expected.Size || hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
		return errors.New("S3 ciphertext differs from the recorded size or SHA-256")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := errors.Join(file.Sync(), file.Close()); err != nil {
		return err
	}
	// Reject aliases introduced while the network transfer was in progress.
	present, err = backupfs.Destination(root, name, false)
	if err != nil {
		return err
	}
	if present && replace {
		if err := root.Rename(temporary, name); err != nil {
			return err
		}
	} else {
		// Link provides exclusive publication; Rename could overwrite a file which
		// appeared between the preceding check and this operation.
		if err := root.Link(temporary, name); err != nil {
			return err
		}
		if err := root.Remove(temporary); err != nil {
			return err
		}
	}
	return backupfs.SyncDirectory(parent)
}

type recoveryRetrievalWriter struct {
	ctx                context.Context
	output             io.Writer
	directory          string
	remaining, checked int64
}

func (w *recoveryRetrievalWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if int64(len(p)) > w.remaining {
		return 0, errors.New("retrieval exceeded its byte budget")
	}
	if w.checked <= 0 {
		if err := backupfs.CheckStagingSpace(w.directory, min(w.remaining, 64<<20)); err != nil {
			return 0, err
		}
		w.checked = 64 << 20
	}
	n, err := w.output.Write(p)
	w.remaining -= int64(n)
	w.checked -= int64(n)
	return n, err
}

func (b *Backup) RetrieveRecoveryBackup(ctx context.Context, request contract.RecoveryRetrieveRequest) (contract.RecoveryBackup, error) {
	var empty contract.RecoveryBackup
	if b.store == nil {
		return empty, errors.New("backup store is unavailable")
	}
	if !request.ConfirmDownload {
		return empty, errors.New("S3 retrieval requires explicit download consent")
	}
	if !b.mu.TryLock() {
		return empty, errBackupBusy
	}
	defer func() { b.mu.Unlock(); b.reschedule() }()
	if b.restoring.Load() || b.recoveryReaders[request.ID] > 0 {
		return empty, errBackupBusy
	}
	ctx, cancel := b.operationContext(ctx)
	defer cancel()
	job, err := b.store.RecoveryJob(ctx, request.ID)
	if err != nil {
		return empty, err
	}
	if job.State != "verified" || job.Target != "s3" {
		return empty, errors.New("only a verified S3 backup can be retrieved")
	}
	policy, err := backupstore.NormalizeRecoveryPolicy(job.Policy)
	if err != nil {
		return empty, err
	}
	ctx, policyCancel := context.WithTimeout(ctx, time.Duration(policy.TimeoutMinutes)*time.Minute)
	defer policyCancel()
	options, err := b.store.Get(ctx)
	if err != nil {
		return empty, err
	}
	digest, err := recoveryS3Digest(options.S3)
	if err != nil || digest != job.S3Digest || !options.S3.Enabled {
		return empty, errors.New("S3 destination or credentials changed; restore the original configuration before retrieving this backup")
	}
	path, err := backupfs.ArchivePath(b.dir, job.ID)
	if err != nil {
		return empty, err
	}
	root, err := os.OpenRoot(b.dir)
	if err != nil {
		return empty, err
	}
	defer root.Close()
	relative, err := filepath.Rel(b.dir, path)
	if err != nil {
		return empty, err
	}
	present, err := backupfs.Destination(root, relative, true)
	if err != nil {
		return empty, err
	}
	if present {
		file, err := openManagedRecoveryArchive(b.dir, job.ID)
		if err != nil {
			return empty, err
		}
		info, infoErr := file.Stat()
		size, digest, checkErr := backupfs.DigestArchiveFile(ctx, file)
		_ = file.Close()
		private := infoErr == nil && (runtime.GOOS == "windows" || info.Mode().Perm()&0o077 == 0)
		if checkErr == nil && private && size == job.Size && digest == job.SHA256 {
			job.LocalState = "present"
			return job.RecoveryBackup, nil
		}
		if !request.ConfirmReplace {
			return empty, errors.New("local archive differs; explicit replacement consent is required")
		}
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	job.Retrieval, job.RetrievalErrorCode, job.LocalState = "running", "", ""
	if err := b.store.SaveRecoveryJob(ctx, job, job.State); err != nil {
		return empty, err
	}
	transferErr := FetchArchive(ctx, path, options.S3, job.RecoveryBackup, b.proxy, request.ConfirmReplace)
	job.Retrieval = "verified"
	if transferErr != nil {
		job.Retrieval, job.RetrievalErrorCode = "failed", "retrieval_failed"
		if ctx.Err() != nil {
			job.Retrieval, job.RetrievalErrorCode = "cancelled", "retrieval_cancelled"
		}
	} else {
		job.RetrievedAt = time.Now().UTC()
	}
	// This is ciphertext verification only. Never promote an earlier failed
	// authenticated archive check or claim that a deployment can start.
	recordCtx, recordCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer recordCancel()
	if err := b.store.SaveRecoveryJob(recordCtx, job, job.State); err != nil {
		return empty, err
	}
	if transferErr != nil {
		return empty, transferErr
	}
	job.LocalState = "present"
	return job.RecoveryBackup, nil
}

func localRecoveryArchiveState(directory string, item contract.RecoveryBackup) string {
	file, err := openManagedRecoveryArchive(directory, item.ID)
	if errors.Is(err, os.ErrNotExist) {
		return "missing"
	}
	if err != nil {
		return "unavailable"
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != item.Size || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return "unavailable"
	}
	return "present"
}

func (b *Backup) recoverInterruptedRetrievals(ctx context.Context) error {
	items, err := b.store.RecoveryRetentionCandidates(ctx)
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.Retrieval != "running" {
			continue
		}
		job, err := b.store.RecoveryJob(ctx, item.ID)
		if err != nil {
			return err
		}
		path, err := backupfs.ArchivePath(b.dir, job.ID)
		if err != nil {
			return err
		}
		root, err := os.OpenRoot(b.dir)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(b.dir, path+".download")
		if err == nil {
			var present bool
			present, err = backupfs.Destination(root, relative, false)
			if err == nil && present {
				err = root.Remove(relative)
			}
		}
		_ = root.Close()
		if err != nil {
			return err
		}
		job.Retrieval, job.RetrievalErrorCode = "interrupted", "retrieval_interrupted"
		if err := b.store.SaveRecoveryJob(ctx, job, job.State); err != nil {
			return err
		}
	}
	return nil
}
