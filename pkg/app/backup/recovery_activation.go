package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
)

// activationCheckpoint is injected only by deterministic fault tests. Returning
// an error models a failed operation; panic/process exit models a crash without
// executing rollback defers. Production passes nil.
func activateRecoverySet(ctx context.Context, directory string, tx *recoveryTransaction, checkpoint func(string) error) (resultErr error) {
	if runtime.GOOS == "windows" {
		return errors.New("durable offline activation requires a filesystem with directory synchronization")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	var originals int64
	for i := range tx.Moves {
		move := &tx.Moves[i]
		present, err := recoveryDestination(root, move.Path, false)
		if err != nil || present != move.HadOriginal {
			return errors.New("recovery target changed since its replacement plan")
		}
		if present {
			file, err := root.Open(move.Path)
			if err != nil {
				return err
			}
			digest, size, hashErr := hashRecoveryOriginal(ctx, file, backupstore.MaxRecoveryDataBytes-originals)
			hashErr = errors.Join(hashErr, file.Sync(), file.Close())
			if hashErr != nil {
				return hashErr
			}
			move.OriginalSHA256 = digest
			originals += size
		}
	}
	if err := root.Mkdir(tx.point(), 0o700); err != nil {
		return err
	}
	if err := planRecoveryDirectories(root, tx); err != nil {
		return err
	}
	for _, move := range tx.Moves {
		if move.Install {
			file, err := root.Open(filepath.Join(tx.Stage, move.Path))
			if err != nil {
				return err
			}
			err = errors.Join(file.Sync(), file.Close())
			if err != nil {
				return err
			}
		}
	}
	if err := saveRecoveryPointRecord(directory, *tx); err != nil {
		return err
	}
	if err := saveRecoveryTransaction(directory, *tx); err != nil {
		return err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, rollbackRecoverySet(directory, tx))
		}
	}()
	for _, move := range tx.Moves {
		if _, err := recoveryDestination(root, filepath.Join(tx.point(), move.Path), true); err != nil {
			return err
		}
		if _, err := recoveryDestination(root, move.Path, true); err != nil {
			return err
		}
	}
	check := func(label string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if checkpoint != nil {
			return checkpoint(label)
		}
		return nil
	}
	for _, move := range tx.Moves {
		if err := check("before:" + move.Path); err != nil {
			return err
		}
		if move.HadOriginal {
			if err := root.Rename(move.Path, filepath.Join(tx.point(), move.Path)); err != nil {
				return err
			}
			if err := syncRecoveryParents(directory, move.Path, filepath.Join(tx.point(), move.Path)); err != nil {
				return err
			}
		}
		if err := check("saved:" + move.Path); err != nil {
			return err
		}
		if move.Install {
			staged := filepath.Join(tx.Stage, filepath.FromSlash(move.Path))
			if err := root.Rename(staged, move.Path); err != nil {
				return err
			}
			if err := syncRecoveryParents(directory, staged, move.Path); err != nil {
				return err
			}
		}
		if err := check("installed:" + move.Path); err != nil {
			return err
		}
	}
	tx.Phase = "awaiting_startup"
	return saveRecoveryTransaction(directory, *tx)
}

func syncRecoveryParents(directory string, paths ...string) error {
	for _, name := range paths {
		if err := syncRecoveryDirectory(filepath.Dir(filepath.Join(directory, name))); err != nil {
			return err
		}
	}
	return nil
}

// Move original inodes back without needing another database-sized disk copy.
// A rollback consumes those point files. Their recorded digests distinguish
// already-restored originals from missing/corrupt recovery material on retry.
func rollbackRecoverySet(directory string, tx *recoveryTransaction) error {
	return rollbackRecoverySetCheckpoint(directory, tx, nil)
}

func rollbackRecoverySetCheckpoint(directory string, tx *recoveryTransaction, checkpoint func(string)) error {
	if err := sqlite.RequireClosed(filepath.Join(directory, "state.db"), filepath.Join(directory, "management.db")); err != nil {
		return err
	}
	if tx.Phase != "rolling_back" {
		tx.Phase = "rolling_back"
		if err := saveRecoveryTransaction(directory, *tx); err != nil {
			return err
		}
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, move := range tx.Moves {
		saved := filepath.Join(tx.point(), move.Path)
		present, err := recoveryDestination(root, saved, false)
		if err != nil {
			return err
		}
		if move.HadOriginal && !present {
			file, err := root.Open(move.Path)
			if err != nil {
				return err
			}
			digest, _, hashErr := hashRecoveryOriginal(context.Background(), file, backupstore.MaxRecoveryDataBytes)
			hashErr = errors.Join(hashErr, file.Close())
			if hashErr != nil || digest != move.OriginalSHA256 {
				return errors.New("original recovery file is missing or changed; automatic rollback refused")
			}
			// Activation had not saved it, or a previous rollback already put
			// this exact original back before its process was interrupted.
			continue
		}
		live, err := recoveryDestination(root, move.Path, move.HadOriginal)
		if err != nil {
			return err
		}
		if !move.HadOriginal {
			if live {
				if err := root.Remove(move.Path); err != nil {
					return err
				}
				if err := syncRecoveryParents(directory, move.Path); err != nil {
					return err
				}
			}
			continue
		}
		input, err := root.Open(saved)
		if err != nil {
			return err
		}
		digest, _, hashErr := hashRecoveryOriginal(context.Background(), input, backupstore.MaxRecoveryDataBytes)
		hashErr = errors.Join(hashErr, input.Close())
		if hashErr != nil || digest != move.OriginalSHA256 {
			return errors.New("saved recovery file is corrupt; automatic rollback refused")
		}
		if err := root.Rename(saved, move.Path); err != nil {
			return err
		}
		if err := syncRecoveryParents(directory, saved, move.Path); err != nil {
			return err
		}
		if checkpoint != nil {
			checkpoint("restored:" + move.Path)
		}
	}
	for _, created := range tx.CreatedDirectories {
		info, err := root.Lstat(created)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("created recovery directory changed before rollback")
		}
		destination := filepath.Join(tx.point(), "discarded", created)
		if _, err := recoveryDestination(root, filepath.Join(destination, "placeholder"), true); err != nil {
			return err
		}
		// The helper creates the destination for a placeholder. Rename needs
		// its parents but an absent final directory.
		if err := root.Remove(destination); err != nil {
			return err
		}
		if err := root.Rename(created, destination); err != nil {
			return err
		}
		if err := syncRecoveryParents(directory, created, destination); err != nil {
			return err
		}
	}
	point := *tx
	point.Phase = "rolled_back"
	// A managed startup binding is part of the recovery transaction. Persist
	// its previous value before removing the journal, so a crash cannot start
	// restored original files using the failed deployment's TLS/file inputs.
	if err := saveRecoveryResult(directory, point, "rolled_back"); err != nil && (tx.AdoptStartup || tx.PreviousStartup != nil) {
		return err
	}
	if err := root.Remove(recoveryJournalName); err != nil {
		return err
	}
	// History is best effort on a failing/full filesystem. It must not stop
	// the original inodes from becoming usable again after rollback.
	_ = saveRecoveryPointRecord(directory, point)
	return syncRecoveryDirectory(directory)
}

func hashRecoveryOriginal(ctx context.Context, file *os.File, limit int64) (string, int64, error) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
		return "", 0, errors.New("recovery original-file set exceeds its size budget")
	}
	hash := sha256.New()
	buffer := make([]byte, 32<<10)
	var size int64
	for {
		if err := ctx.Err(); err != nil {
			return "", 0, err
		}
		n, readErr := file.Read(buffer[:min(int64(len(buffer)), limit-size+1)])
		if n > 0 {
			_, _ = hash.Write(buffer[:n])
			size += int64(n)
			if size > limit {
				return "", 0, errors.New("recovery original grew past its size budget")
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return "", 0, readErr
		}
	}
	after, err := file.Stat()
	if err != nil || size != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return "", 0, errors.New("recovery original changed while being saved")
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func planRecoveryDirectories(root *os.Root, tx *recoveryTransaction) error {
	missing := map[string]bool{}
	for _, move := range tx.Moves {
		parent := ""
		parts := strings.Split(filepath.ToSlash(move.Path), "/")
		for _, part := range parts[:len(parts)-1] {
			parent = filepath.Join(parent, part)
			info, err := root.Lstat(parent)
			if errors.Is(err, os.ErrNotExist) {
				missing[parent] = true
				break
			}
			if err != nil {
				return err
			}
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("recovery parent directory is not a real directory")
			}
		}
	}
	tx.CreatedDirectories = slices.Sorted(maps.Keys(missing))
	return nil
}
