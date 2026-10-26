package app

import (
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
	"uuid"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/store"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicfile"
)

const recoveryJournalName = ".recovery-transaction.json"
const maxRecoveryJournalBytes = 4 << 20

type recoveryMove struct {
	Path           string `json:"path"`
	HadOriginal    bool   `json:"hadOriginal"`
	Install        bool   `json:"install"`
	OriginalSHA256 string `json:"originalSha256,omitempty"`
}

type recoveryTransaction struct {
	Version            int                      `json:"version"`
	ID                 string                   `json:"id"`
	BackupID           string                   `json:"backupId"`
	InstanceID         string                   `json:"instanceId,omitempty"`
	Phase              string                   `json:"phase"`
	Stage              string                   `json:"stage"`
	CreatedAt          time.Time                `json:"createdAt"`
	Runtime            contract.RecoveryRuntime `json:"runtime"`
	Moves              []recoveryMove           `json:"moves"`
	CreatedDirectories []string                 `json:"createdDirectories,omitempty"`
}

func (t recoveryTransaction) point() string { return ".recovery-point-" + t.ID }

func readRecoveryTransaction(directory string) (*recoveryTransaction, error) {
	root, err := os.OpenRoot(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(recoveryJournalName)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxRecoveryJournalBytes {
		return nil, errors.New("invalid recovery transaction journal")
	}
	file, err := root.Open(recoveryJournalName)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxRecoveryJournalBytes+1))
	if err != nil || len(data) > maxRecoveryJournalBytes {
		return nil, errors.New("cannot read bounded recovery transaction journal")
	}
	var tx recoveryTransaction
	if err := json.Unmarshal(data, &tx, json.RejectUnknownMembers(true)); err != nil {
		return nil, errors.New("invalid recovery transaction journal")
	}
	if err := tx.validate(); err != nil {
		return nil, err
	}
	for _, move := range tx.Moves {
		if move.HadOriginal && move.OriginalSHA256 == "" {
			return nil, errors.New("recovery journal lacks original-file integrity metadata")
		}
	}
	return &tx, nil
}

func (t recoveryTransaction) validate() error {
	for _, id := range []string{t.ID, t.BackupID, t.InstanceID} {
		value, err := uuid.Parse(id)
		if err != nil || value.String() != id || value == (uuid.UUID{}) {
			return errors.New("invalid recovery transaction identifier")
		}
	}
	if t.Version != 1 || t.CreatedAt.IsZero() || !slices.Contains([]string{"activating", "awaiting_startup", "checking", "committed", "rolling_back"}, t.Phase) {
		return errors.New("unsupported recovery transaction")
	}
	stageBase := filepath.Base(t.Stage)
	stageParent := filepath.Dir(t.Stage)
	ownedStage := stageParent == "."
	if filepath.Dir(stageParent) == ".recovery-imports" {
		_, err := recoveryImportPath(filepath.Base(stageParent))
		ownedStage = err == nil
	}
	if !ownedStage || t.Stage != filepath.Clean(t.Stage) || !strings.HasPrefix(stageBase, ".recovery-stage-") || len(t.Stage) > 128 {
		return errors.New("invalid recovery staging location")
	}
	if err := store.ValidateRecoveryRuntime(t.Runtime); err != nil {
		return err
	}
	if len(t.Moves) == 0 || len(t.Moves) > 2*store.MaxRecoveryFiles+8 {
		return errors.New("invalid recovery replacement count")
	}
	names := map[string]bool{}
	for _, move := range t.Moves {
		if move.OriginalSHA256 != "" {
			digest, err := hex.DecodeString(move.OriginalSHA256)
			if err != nil || len(digest) != 32 || !move.HadOriginal {
				return errors.New("invalid recovery original-file digest")
			}
		}
		// SQLite sidecars can be saved/removed by the transaction, but can never
		// be installed from an archive. All other paths use archive validation.
		sidecar := false
		for _, db := range []string{"state.db", "management.db"} {
			for _, suffix := range []string{"-wal", "-shm", "-journal"} {
				sidecar = sidecar || move.Path == db+suffix
			}
		}
		if sidecar {
			if move.Install {
				return errors.New("recovery cannot install a SQLite sidecar")
			}
		} else if err := store.ValidateRecoveryDestination(filepath.ToSlash(move.Path)); err != nil {
			return err
		}
		key := strings.ToLower(move.Path)
		if names[key] {
			return errors.New("duplicate recovery transaction destination")
		}
		names[key] = true
	}
	for name := range names {
		for parent := filepath.Dir(name); parent != "."; parent = filepath.Dir(parent) {
			if names[parent] {
				return errors.New("conflicting recovery transaction destinations")
			}
		}
	}
	if len(t.CreatedDirectories) > len(t.Moves) {
		return errors.New("invalid created recovery directory count")
	}
	for _, directory := range t.CreatedDirectories {
		if err := store.ValidateRecoveryDestination(filepath.ToSlash(directory)); err != nil {
			return err
		}
		owned := false
		for name := range names {
			owned = owned || strings.HasPrefix(name, strings.ToLower(filepath.ToSlash(directory))+"/")
		}
		if !owned {
			return errors.New("unowned directory in recovery transaction")
		}
	}
	return nil
}

func saveRecoveryTransaction(directory string, tx recoveryTransaction) error {
	if err := tx.validate(); err != nil {
		return err
	}
	data, err := json.Marshal(tx)
	if err != nil || len(data) > maxRecoveryJournalBytes {
		return errors.New("recovery transaction exceeds journal limit")
	}
	if err := atomicfile.WriteFile(filepath.Join(directory, recoveryJournalName), data, 0o600); err != nil {
		return err
	}
	return syncRecoveryDirectory(directory)
}

func saveRecoveryPointRecord(directory string, tx recoveryTransaction) error {
	data, err := json.Marshal(tx)
	if err != nil || len(data) > maxRecoveryJournalBytes {
		return errors.New("recovery point metadata exceeds its limit")
	}
	metadata := filepath.Join(directory, tx.point(), ".recovery-meta")
	if err := os.MkdirAll(metadata, 0o700); err != nil {
		return err
	}
	if err := atomicfile.WriteFile(filepath.Join(metadata, "transaction.json"), data, 0o600); err != nil {
		return err
	}
	return errors.Join(syncRecoveryDirectory(metadata), syncRecoveryDirectory(filepath.Dir(metadata)), syncRecoveryDirectory(directory))
}

func recoveryResult(tx recoveryTransaction, state string) contract.RecoveryRestoreResult {
	return contract.RecoveryRestoreResult{BackupID: tx.BackupID, TransactionID: tx.ID, InstanceID: tx.InstanceID,
		RecoveryPoint: tx.point(), State: state, Runtime: tx.Runtime}
}

func saveRecoveryResult(directory string, tx recoveryTransaction, state string) error {
	data, err := json.Marshal(recoveryResult(tx, state))
	if err != nil {
		return err
	}
	if err := atomicfile.WriteFile(filepath.Join(directory, ".recovery-last-result.json"), data, 0o600); err != nil {
		return err
	}
	return syncRecoveryDirectory(directory)
}

func syncRecoveryDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return errors.ErrUnsupported
	}
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

// Reject symlink components even when they stay inside the root: a transaction
// must not overwrite a second configuration through a directory alias.
func recoveryDestination(root *os.Root, name string, createParents bool) (bool, error) {
	parts := strings.Split(filepath.ToSlash(name), "/")
	parent := ""
	for _, part := range parts[:len(parts)-1] {
		parent = filepath.Join(parent, part)
		info, err := root.Lstat(parent)
		if errors.Is(err, os.ErrNotExist) && createParents {
			if err := root.Mkdir(parent, 0o700); err != nil {
				return false, err
			}
			directory, err := root.Open(filepath.Dir(parent))
			if err != nil {
				return false, err
			}
			err = errors.Join(directory.Sync(), directory.Close())
			if err != nil {
				return false, err
			}
			continue
		}
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false, errors.New("recovery destination parent must be a real directory")
		}
	}
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("recovery destination must be a regular file")
	}
	return true, nil
}
