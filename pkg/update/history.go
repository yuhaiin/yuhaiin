package update

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	contractupdate "github.com/Asutorufa/yuhaiin/pkg/contract/update"
)

const maxHistory = 2

// HistoryDirectory is deliberately separate from the executable's directory.
// It may live on a different filesystem, so snapshots are copied, not renamed.
func HistoryDirectory(dataDir string) string {
	return filepath.Join(dataDir, "update", "versions")
}

func validHistoryID(id string) bool {
	if len(id) != sha256.Size*2 {
		return false
	}
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == sha256.Size && strings.ToLower(id) == id
}

func checkHistoryDirectory(dir string, create bool) error {
	if create {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("update history directory must be a real directory")
	}
	// Only the service account may modify these privileged rollback binaries.
	if info.Mode().Perm()&0022 != 0 {
		return errors.New("update history directory must not be group/world writable")
	}
	return nil
}

func historyPaths(dir, id string) (string, string) {
	return filepath.Join(dir, id+".bin"), filepath.Join(dir, id+".json")
}

// ListHistory returns only entries created by the update helper, never
// arbitrary paths submitted by clients.
func ListHistory(dataDir string) ([]contractupdate.HistoryEntry, error) {
	dir := HistoryDirectory(dataDir)
	if err := checkHistoryDirectory(dir, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []contractupdate.HistoryEntry{}, nil
		}
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	history := make([]contractupdate.HistoryEntry, 0, maxHistory)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !validHistoryID(id) {
			continue
		}
		binaryPath, metadataPath := historyPaths(dir, id)
		metaInfo, err := os.Lstat(metadataPath)
		if err != nil || !metaInfo.Mode().IsRegular() || metaInfo.Size() > 8192 {
			continue
		}
		binInfo, err := os.Lstat(binaryPath)
		if err != nil || !binInfo.Mode().IsRegular() {
			continue
		}
		raw, err := os.ReadFile(metadataPath)
		if err != nil {
			continue
		}
		var item contractupdate.HistoryEntry
		if json.Unmarshal(raw, &item) != nil || item.ID != id || item.Size != binInfo.Size() {
			continue
		}
		history = append(history, item)
	}
	slices.SortFunc(history, func(a, b contractupdate.HistoryEntry) int {
		if a.SavedAt.Equal(b.SavedAt) {
			return strings.Compare(b.ID, a.ID)
		}
		return b.SavedAt.Compare(a.SavedAt)
	})
	return history, nil
}

// SaveHistory snapshots the running version before it is replaced. Do not
// prune yet: installation or service restart might still fail.
func SaveHistory(dataDir, executable, version, commit string) error {
	dir := HistoryDirectory(dataDir)
	if err := checkHistoryDirectory(dir, true); err != nil {
		return err
	}
	source, err := os.Open(executable)
	if err != nil {
		return err
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("current executable is not a regular file")
	}

	tmp, err := os.CreateTemp(dir, ".binary-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	hash := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(tmp, hash), source)
	if copyErr != nil {
		_ = tmp.Close()
		return copyErr
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	id := hex.EncodeToString(hash.Sum(nil))
	binPath, metaPath := historyPaths(dir, id)
	if err := os.Rename(tmpPath, binPath); err != nil {
		return err
	}

	item := contractupdate.HistoryEntry{
		ID: id, Version: version, Commit: commit, Size: size, SavedAt: time.Now().UTC(),
	}
	raw, err := json.MarshalIndent(item, "", "  ")
	if err != nil {
		return err
	}
	metaTmp, err := os.CreateTemp(dir, ".metadata-*")
	if err != nil {
		return err
	}
	metaTmpPath := metaTmp.Name()
	defer os.Remove(metaTmpPath)
	if _, err := metaTmp.Write(raw); err != nil {
		_ = metaTmp.Close()
		return err
	}
	if err := metaTmp.Sync(); err != nil {
		_ = metaTmp.Close()
		return err
	}
	if err := metaTmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(metaTmpPath, metaPath); err != nil {
		return err
	}
	return syncHistoryDir(dir)
}

func syncHistoryDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	// Some platforms/filesystems do not support syncing directories.
	if err := f.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}

// StageHistory verifies archived bytes before giving them to the platform
// installer, and puts the staged copy beside the target for atomic replacement.
func StageHistory(dataDir, id, stageDir string) (string, error) {
	if !validHistoryID(id) {
		return "", errors.New("invalid history ID")
	}
	entries, err := ListHistory(dataDir)
	if err != nil {
		return "", err
	}
	exists := slices.ContainsFunc(entries, func(item contractupdate.HistoryEntry) bool { return item.ID == id })
	if !exists {
		return "", errors.New("history version not found")
	}
	path, _ := historyPaths(HistoryDirectory(dataDir), id)
	source, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer source.Close()
	tmp, err := os.CreateTemp(stageDir, ".yuhaiin-rollback-*")
	if err != nil {
		return "", err
	}
	staged := tmp.Name()
	defer func() { _ = tmp.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, hash), source); err != nil {
		_ = os.Remove(staged)
		return "", err
	}
	if hex.EncodeToString(hash.Sum(nil)) != id {
		_ = os.Remove(staged)
		return "", fmt.Errorf("history checksum mismatch for %s", id)
	}
	if err := tmp.Chmod(0755); err != nil {
		_ = os.Remove(staged)
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		_ = os.Remove(staged)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(staged)
		return "", err
	}
	return staged, nil
}

// PruneHistory runs only after the replacement has been restarted. The
// selected archive is now active and is no longer a rollback candidate.
func PruneHistory(dataDir, activeExecutable string) error {
	entries, err := ListHistory(dataDir)
	if err != nil {
		return err
	}
	activeHash, err := fileSHA256(activeExecutable)
	if err != nil {
		return err
	}
	kept := 0
	dir := HistoryDirectory(dataDir)
	for _, entry := range entries {
		if entry.ID != activeHash && kept < maxHistory {
			kept++
			continue
		}
		binary, metadata := historyPaths(dir, entry.ID)
		if err := os.Remove(metadata); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Remove(binary); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return syncHistoryDir(dir)
}
