package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"uuid"

	backupfs "github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/backupfs"
	"github.com/Asutorufa/yuhaiin/pkg/app/backup/recovery"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/management/permission"
	"github.com/Asutorufa/yuhaiin/pkg/s3"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	backuparchive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

const recoveryImportLifetime = 30 * time.Minute

func recoveryImportOwner(ctx context.Context) string {
	if id := permission.ActorID(ctx); id != "" {
		return id
	}
	// Embedded management hosts may intentionally omit identity middleware.
	// Their existing route authorization remains responsible for admission.
	return "local-management"
}

// UploadRecoveryImport streams ciphertext into a private, expiring owned file.
// One existing Backup lease bounds concurrent upload/decryption/transfer work.
func (b *Backup) UploadRecoveryImport(ctx context.Context, input io.ReadCloser, size int64) (_ contract.RecoveryImport, resultErr error) {
	var empty contract.RecoveryImport
	if b.restoring.Load() {
		return empty, errBackupBusy
	}
	if b.store == nil {
		return empty, errors.New("backup store is unavailable")
	}
	if size == 0 || size > s3.MaxObjectBytes || size < -1 {
		return empty, errors.New("encrypted recovery upload must be between one byte and 100 GiB")
	}
	if !b.mu.TryLock() {
		return empty, errBackupBusy
	}
	defer func() { b.mu.Unlock(); b.reschedule() }()
	ctx, cancel := b.operationContext(ctx)
	defer cancel()
	stopRead := context.AfterFunc(ctx, func() { _ = input.Close() })
	defer stopRead()
	defer input.Close()
	if err := b.pruneRecoveryImportsLocked(ctx, false); err != nil {
		return empty, err
	}
	ids, err := b.store.RecoveryImportIDs(ctx)
	if err != nil {
		return empty, err
	}
	var used int64
	for _, id := range ids {
		item, err := b.store.RecoveryImport(ctx, id)
		if err != nil {
			return empty, err
		}
		used += item.Size
	}
	budget := s3.MaxObjectBytes - used
	if budget <= 0 || (size > 0 && size > budget) {
		return empty, errors.New("combined encrypted recovery uploads exceed 100 GiB")
	}
	if err := backupfs.CheckStagingSpace(b.dir, max(size, 0)); err != nil {
		return empty, err
	}
	now := time.Now().UTC()
	item := backupstore.RecoveryImportRecord{ID: uuid.New().String(), CreatedAt: now, ExpiresAt: now.Add(recoveryImportLifetime), State: "uploading", Owner: recoveryImportOwner(ctx)}
	name, _ := backupfs.ImportPath(item.ID)
	root, err := os.OpenRoot(b.dir)
	if err != nil {
		return empty, err
	}
	defer root.Close()
	if err := prepareRecoveryImportNamespace(root); err != nil {
		return empty, err
	}
	container := filepath.Dir(name)
	// Only an exclusively created directory belongs to this request. Never
	// reuse or clean up a pre-existing container, even on a UUID collision.
	if err := root.Mkdir(container, 0o700); err != nil {
		return empty, err
	}
	registered := false
	defer func() {
		if resultErr == nil {
			return
		}
		// Unpublished ciphertext must release its disk budget even when the
		// registry cannot write (for example, after exhausting filesystem space).
		// Interrupted registry rows are reconciled by the existing startup sweep.
		if err := root.RemoveAll(container); err != nil {
			return
		}
		if err := backupfs.SyncDirectory(filepath.Join(b.dir, ".recovery-imports")); err != nil {
			return
		}
		if registered {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			_ = b.deleteRecoveryImportLocked(cleanup, item)
		}
	}()
	if err := backupfs.SyncDirectory(filepath.Join(b.dir, ".recovery-imports")); err != nil {
		return empty, err
	}
	if err := b.store.AddRecoveryImport(ctx, item); err != nil {
		return empty, err
	}
	registered = true
	output, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return empty, err
	}
	defer output.Close()
	hash := sha256.New()
	item.Size, err = copyRecoveryImport(ctx, input, io.MultiWriter(output, hash), budget, func(bytes int64) error { return backupfs.CheckStagingSpace(b.dir, bytes) })
	if err != nil {
		return empty, err
	}
	if item.Size == 0 || (size >= 0 && size != item.Size) {
		return empty, errors.New("incomplete encrypted recovery upload")
	}
	if err := errors.Join(output.Sync(), backupfs.SyncDirectory(filepath.Join(b.dir, filepath.Dir(name)))); err != nil {
		return empty, err
	}
	item.State, item.SHA256 = "uploaded", hex.EncodeToString(hash.Sum(nil))
	if err := b.store.SaveRecoveryImport(ctx, item, "uploading"); err != nil {
		return empty, err
	}
	return item.RecoveryImport, nil
}

func prepareRecoveryImportNamespace(root *os.Root) error {
	const name = ".recovery-imports"
	if err := root.Mkdir(name, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("recovery import namespace must be a real directory")
	}
	return backupfs.SyncDirectory(root.Name())
}

func copyRecoveryImport(ctx context.Context, input io.Reader, output io.Writer, budget int64, checkSpace func(int64) error) (int64, error) {
	buffer := make([]byte, 32<<10)
	var total, checked int64
	emptyReads := 0
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		// Read at most one byte past the remaining budget, including chunked
		// requests. Never consume an arbitrarily large final input chunk.
		n, readErr := input.Read(buffer[:min(int64(len(buffer)), budget-total+1)])
		if n == 0 && readErr == nil {
			emptyReads++
			if emptyReads >= 100 {
				return total, io.ErrNoProgress
			}
		} else {
			emptyReads = 0
		}
		if n > 0 {
			if int64(n) > budget-total {
				return total, errors.New("encrypted recovery upload exceeds its budget")
			}
			if total >= checked {
				if err := checkSpace(64 << 20); err != nil {
					return total, err
				}
				checked = total + (64 << 20)
			}
			written, err := output.Write(buffer[:n])
			total += int64(written)
			if err != nil {
				return total, err
			}
			if written != n {
				return total, io.ErrShortWrite
			}
		}
		if errors.Is(readErr, io.EOF) {
			return total, nil
		}
		if readErr != nil {
			if ctx.Err() != nil {
				return total, ctx.Err()
			}
			return total, readErr
		}
	}
}

func (b *Backup) ownedRecoveryImport(ctx context.Context, id string) (backupstore.RecoveryImportRecord, error) {
	item, err := b.store.RecoveryImport(ctx, id)
	if err != nil {
		return item, err
	}
	if item.Owner != recoveryImportOwner(ctx) || !item.ExpiresAt.After(time.Now()) || (item.State != "uploaded" && item.State != "previewed") {
		return item, errors.New("recovery import is unavailable or expired")
	}
	return item, nil
}

func (b *Backup) RecoveryImports(ctx context.Context) ([]contract.RecoveryImport, error) {
	out := []contract.RecoveryImport{}
	if b.store == nil {
		return nil, errors.New("backup store is unavailable")
	}
	ids, err := b.store.RecoveryImportIDs(ctx)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		item, err := b.store.RecoveryImport(ctx, id)
		if err != nil {
			return nil, err
		}
		if item.Owner == recoveryImportOwner(ctx) && item.ExpiresAt.After(time.Now()) && item.State != "deleting" {
			out = append(out, item.RecoveryImport)
		}
	}
	return out, nil
}

func (b *Backup) PreviewRecoveryImport(ctx context.Context, request contract.RecoveryImportPreviewRequest) (contract.RecoveryImport, error) {
	var empty contract.RecoveryImport
	if b.restoring.Load() {
		return empty, errBackupBusy
	}
	if b.store == nil {
		return empty, errors.New("backup store is unavailable")
	}
	if (request.Mode != "original" && request.Mode != "clone") || len(request.Identity) > 512 || len(request.Passphrase) > 4096 {
		return empty, errors.New("invalid recovery preview mode or key input")
	}
	if !b.mu.TryLock() {
		return empty, errBackupBusy
	}
	defer func() { b.mu.Unlock(); b.reschedule() }()
	ctx, cancel := b.operationContext(ctx)
	defer cancel()
	item, err := b.ownedRecoveryImport(ctx, request.ID)
	if err != nil {
		return empty, err
	}
	name, _ := backupfs.ImportPath(item.ID)
	root, err := os.OpenRoot(b.dir)
	if err != nil {
		return empty, err
	}
	defer root.Close()
	if exists, err := backupfs.Destination(root, name, false); err != nil || !exists {
		return empty, errors.New("recovery upload is missing")
	}
	file, err := root.Open(name)
	if err != nil {
		return empty, err
	}
	defer file.Close()
	size, digest, err := backupfs.DigestArchiveFile(ctx, file)
	if err != nil || size != item.Size || digest != item.SHA256 {
		return empty, errors.New("encrypted recovery upload changed")
	}
	prepared, err := recovery.PrepareImport(ctx, b.dir, item.ID, file, backuparchive.Decryption{Identity: request.Identity, Passphrase: request.Passphrase}, request.Mode)
	if err != nil {
		return empty, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = prepared.Close()
		}
	}()
	if !item.ExpiresAt.After(time.Now()) {
		return empty, errors.New("recovery import expired during preview")
	}
	previous := item
	item.State, item.Stage, item.Plan, item.PreviewID, item.Preview = "previewed", prepared.Stage, prepared.Plan, prepared.ID, &prepared.Preview
	item.ErrorCode, item.Activation = "", nil
	if err := b.store.SaveRecoveryImport(ctx, item, previous.State); err != nil {
		return empty, err
	}
	keep = true
	if previous.Stage != "" && previous.Stage != item.Stage {
		_ = removeRecoveryImportStage(root, item.ID, previous.Stage)
	}
	return item.RecoveryImport, nil
}

func (b *Backup) DiscardRecoveryImport(ctx context.Context, id string) error {
	if b.store == nil {
		return errors.New("backup store is unavailable")
	}
	if !b.mu.TryLock() {
		return errBackupBusy
	}
	defer func() { b.mu.Unlock(); b.reschedule() }()
	item, err := b.store.RecoveryImport(ctx, id)
	if err != nil {
		return err
	}
	if item.Owner != recoveryImportOwner(ctx) {
		return errors.New("recovery import is unavailable")
	}
	if item.State == "activating" {
		lease, err := lockfile.Acquire(filepath.Join(b.dir, ".recovery-maintenance.lock"))
		if err != nil {
			return errors.New("restore maintenance is active; wait for its startup or rollback result")
		}
		defer lease.Close()
	}
	if err := b.deleteRecoveryImportLocked(ctx, item); err != nil {
		return err
	}
	if item.State == "activating" {
		b.restoring.Store(false)
	}
	return nil
}

func removeRecoveryImportStage(root *os.Root, id, stage string) error {
	name, err := backupfs.ImportPath(id)
	if err != nil || filepath.Dir(stage) != filepath.Dir(name) || !strings.HasPrefix(filepath.Base(stage), ".recovery-stage-") || len(stage) > 128 {
		return errors.New("invalid private recovery staging location")
	}
	return root.RemoveAll(stage)
}

func (b *Backup) deleteRecoveryImportLocked(ctx context.Context, item backupstore.RecoveryImportRecord) error {
	if item.State != "deleting" {
		previous := item.State
		item.State = "deleting"
		if err := b.store.SaveRecoveryImport(ctx, item, previous); err != nil {
			return err
		}
	}
	root, err := os.OpenRoot(b.dir)
	if err != nil {
		return err
	}
	defer root.Close()
	name, err := backupfs.ImportPath(item.ID)
	if err != nil {
		return err
	}
	if _, err := backupfs.Destination(root, name, false); err != nil {
		return err
	}
	// The immutable UUID owns this whole private container, including plaintext
	// decoder staging created before a crash could publish its preview record.
	if err := root.RemoveAll(filepath.Dir(name)); err != nil {
		return err
	}
	if err := backupfs.SyncDirectory(filepath.Join(b.dir, ".recovery-imports")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return b.store.DeleteRecoveryImport(ctx, item.ID)
}

func (b *Backup) pruneRecoveryImports(ctx context.Context) error {
	ids, err := b.store.RecoveryImportIDs(ctx)
	if err != nil || len(ids) == 0 {
		return err
	}
	actionable := false
	for _, id := range ids {
		item, err := b.store.RecoveryImport(ctx, id)
		if err != nil {
			return err
		}
		if item.State != "activating" && (item.State == "deleting" || !item.ExpiresAt.After(time.Now())) {
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
	return b.pruneRecoveryImportsLocked(ctx, false)
}

func (b *Backup) pruneRecoveryImportsLocked(ctx context.Context, startup bool) error {
	ids, err := b.store.RecoveryImportIDs(ctx)
	if err != nil {
		return err
	}
	for _, id := range ids {
		item, err := b.store.RecoveryImport(ctx, id)
		if err != nil {
			return err
		}
		if (item.State != "activating" && (item.State == "deleting" || !item.ExpiresAt.After(time.Now()))) || (startup && (item.State == "uploading" || item.State == "activating")) {
			if err := b.deleteRecoveryImportLocked(ctx, item); err != nil {
				return err
			}
		}
	}
	return nil
}
