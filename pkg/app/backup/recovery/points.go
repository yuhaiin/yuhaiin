package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"uuid"

	backupfs "github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/backupfs"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicfile"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

const pointCleanupJournal = ".recovery-point-cleanup.json"
const maxPointCleanup = 32

type pointRecord struct {
	id      string
	created time.Time
	digest  string
	state   string
}
type pointCleanupIntent struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	SHA256  string `json:"sha256"`
}

func pointName(id string) string        { return ".recovery-point-" + id }
func pointGarbageName(id string) string { return ".recovery-pruning-" + id }
func validPointID(value string) bool {
	u, err := uuid.Parse(value)
	return err == nil && u != uuid.Nil() && u.String() == value
}

// PrunePoints is the offline command. It never stops a running deployment or
// opens a live DB writable; the ordinary lifecycle owner excludes restoration.
func PrunePoints(ctx context.Context, directory string, policy contract.PointRetention, maintenance bool) (contract.PointCleanup, error) {
	if !maintenance {
		return contract.PointCleanup{}, errors.New("local rollback-copy deletion requires confirmed stopped writers")
	}
	directory, err := backupfs.CanonicalDirectory(directory)
	if err != nil {
		return contract.PointCleanup{}, err
	}
	owner, err := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
	if err != nil {
		return contract.PointCleanup{}, err
	}
	defer owner.Close()
	if err := requireRecoveryLifecycle(directory, owner); err != nil {
		return contract.PointCleanup{}, err
	}
	return PrunePointsWithLifecycle(ctx, directory, owner, policy)
}

// PrunePointsWithLifecycle is used at CLI startup under its already-held owner,
// before serving management requests. Only finalized old point directories are
// eligible; active/live databases and archives are never cleanup destinations.
func PrunePointsWithLifecycle(ctx context.Context, directory string, owner *os.File, policy contract.PointRetention) (contract.PointCleanup, error) {
	result := contract.PointCleanup{Deleted: []string{}}
	if !policy.Enabled {
		return result, nil
	}
	policy, err := backupstore.NormalizePointRetention(policy)
	if err != nil {
		return result, err
	}
	if err := requireLifecycleOwner(directory, owner); err != nil {
		return result, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return result, err
	}
	defer root.Close()
	pins := map[string]bool{}
	tx, err := readRecoveryTransaction(directory)
	if err != nil {
		return result, err
	}
	if tx != nil {
		pins[tx.ID] = true
	}
	latest, err := LastResult(directory)
	if err != nil {
		return result, err
	}
	if latest != nil {
		pins[latest.TransactionID] = true
	}
	if err := pinConfiguredPoints(ctx, directory, pins); err != nil {
		return result, errors.New("cannot inspect configured local-copy references; cleanup refused")
	}
	if intent, err := readPointCleanup(root); err != nil {
		return result, err
	} else if intent != nil {
		if pins[intent.ID] {
			return result, errors.New("pending cleanup now references a protected recovery point")
		}
		if err := finishPointCleanup(ctx, directory, root, *intent); err != nil {
			return result, err
		}
		result.Deleted = append(result.Deleted, intent.ID)
	}
	points, unknown, err := readPointRecords(ctx, root)
	if err != nil {
		return result, err
	}
	result.Protected = unknown
	slices.SortFunc(points, func(a, b pointRecord) int {
		if value := b.created.Compare(a.created); value != 0 {
			return value
		}
		return strings.Compare(a.id, b.id)
	})
	for _, point := range points {
		if point.state == "committed" {
			pins[point.id] = true
			break
		}
	}
	now := time.Now()
	for index, point := range points {
		if pins[point.id] || index == 0 || point.created.After(now) {
			result.Protected++
			continue
		}
		if index < policy.KeepCount && now.Sub(point.created) <= time.Duration(policy.KeepDays)*24*time.Hour {
			result.Retained++
			continue
		}
		if len(result.Deleted) >= maxPointCleanup {
			result.Retained++
			continue
		}
		if err := ctx.Err(); err != nil {
			return result, err
		}
		// Persist ownership before rename/unlink. An interrupted deletion resumes
		// even when its metadata file was among the already removed children.
		if err := requireUnusedPoint(directory, point.id); err != nil {
			result.Protected++
			continue
		}
		intent := pointCleanupIntent{Version: 1, ID: point.id, SHA256: point.digest}
		data, err := json.Marshal(intent)
		if err != nil {
			return result, err
		}
		if err := writePointIntent(directory, data); err != nil {
			return result, err
		}
		if err := finishPointCleanup(ctx, directory, root, intent); err != nil {
			return result, err
		}
		result.Deleted = append(result.Deleted, point.id)
	}
	return result, nil
}

func readPointRecords(ctx context.Context, root *os.Root) ([]pointRecord, int, error) {
	directory, err := root.Open(".")
	if err != nil {
		return nil, 0, err
	}
	defer directory.Close()
	var points []pointRecord
	unknown, scanned := 0, 0
	for {
		entries, readErr := directory.ReadDir(128)
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return nil, 0, err
			}
			scanned++
			if scanned > 16384 {
				return nil, 0, errors.New("local rollback-copy directory scan exceeds its bound")
			}
			id, point := strings.CutPrefix(entry.Name(), ".recovery-point-")
			if !point {
				continue
			}
			if !validPointID(id) || !entry.IsDir() {
				unknown++
				continue
			}
			record, err := readPointRecord(root, id)
			if err != nil {
				unknown++
				continue
			}
			points = append(points, record)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, 0, readErr
		}
	}
	return points, unknown, nil
}

func readPointRecord(root *os.Root, id string) (pointRecord, error) {
	point, err := root.OpenRoot(pointName(id))
	if err != nil {
		return pointRecord{}, err
	}
	defer point.Close()
	info, err := point.Lstat(filepath.Join(".recovery-meta", "transaction.json"))
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxRecoveryJournalBytes {
		return pointRecord{}, errors.New("unowned local rollback-copy metadata")
	}
	file, err := point.Open(filepath.Join(".recovery-meta", "transaction.json"))
	if err != nil {
		return pointRecord{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxRecoveryJournalBytes+1))
	if err != nil || len(data) > maxRecoveryJournalBytes {
		return pointRecord{}, errors.New("rollback-copy metadata exceeds its bound")
	}
	var tx recoveryTransaction
	if err := json.Unmarshal(data, &tx, json.RejectUnknownMembers(true)); err != nil {
		return pointRecord{}, err
	}
	if tx.ID != id || !slices.Contains([]string{"committed", "rolled_back"}, tx.Phase) {
		return pointRecord{}, errors.New("local rollback-copy is not finalized")
	}
	for _, move := range tx.Moves {
		if move.HadOriginal && move.OriginalSHA256 == "" {
			return pointRecord{}, errors.New("rollback-copy metadata lacks original integrity")
		}
	}
	state := tx.Phase
	tx.Phase = "committed"
	if err := tx.validate(); err != nil {
		return pointRecord{}, err
	}
	digest := sha256.Sum256(data)
	return pointRecord{id: id, created: tx.CreatedAt, digest: hex.EncodeToString(digest[:]), state: state}, nil
}

func readPointCleanup(root *os.Root) (*pointCleanupIntent, error) {
	info, err := root.Lstat(pointCleanupJournal)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
		return nil, errors.New("invalid local point cleanup journal")
	}
	file, err := root.Open(pointCleanupJournal)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(data) > 4096 {
		return nil, errors.New("local point cleanup journal exceeds its bound")
	}
	var intent pointCleanupIntent
	if err := json.Unmarshal(data, &intent, json.RejectUnknownMembers(true)); err != nil {
		return nil, err
	}
	digest, err := hex.DecodeString(intent.SHA256)
	if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != intent.SHA256 || !validPointID(intent.ID) || intent.Version != 1 {
		return nil, errors.New("invalid local point cleanup ownership")
	}
	return &intent, nil
}

func finishPointCleanup(ctx context.Context, directory string, root *os.Root, intent pointCleanupIntent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := requireUnusedPoint(directory, intent.ID); err != nil {
		return err
	}
	source, garbage := pointName(intent.ID), pointGarbageName(intent.ID)
	info, err := root.Lstat(garbage)
	if errors.Is(err, os.ErrNotExist) {
		original, err := root.Lstat(source)
		if errors.Is(err, os.ErrNotExist) {
			return removePointIntent(directory, root)
		}
		if err != nil || !original.IsDir() || original.Mode()&os.ModeSymlink != 0 {
			return errors.New("rollback-copy source changed before cleanup")
		}
		point, err := readPointRecord(root, intent.ID)
		if err != nil || point.digest != intent.SHA256 {
			return errors.New("rollback-copy metadata changed before cleanup")
		}
		if err := root.Rename(source, garbage); err != nil {
			return err
		}
		if err := backupfs.SyncDirectory(directory); err != nil {
			return err
		}
		info, err = root.Lstat(garbage)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if _, err := root.Lstat(source); !errors.Is(err, os.ErrNotExist) {
		return errors.New("cleanup source and garbage locations conflict")
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("cleanup directory was replaced")
	}
	point, err := root.OpenRoot(garbage)
	if err != nil {
		return err
	}
	defer point.Close()
	actual, err := point.Stat(".")
	if err != nil || !os.SameFile(info, actual) {
		return errors.New("cleanup directory ownership changed")
	}
	if err := removePointChildren(ctx, point, ".", 0); err != nil {
		return err
	}
	current, err := root.Lstat(garbage)
	if err != nil || !os.SameFile(info, current) {
		return errors.New("cleanup directory changed before removal")
	}
	if err := root.Remove(garbage); err != nil {
		return err
	}
	if err := backupfs.SyncDirectory(directory); err != nil {
		return err
	}
	return removePointIntent(directory, root)
}

func removePointChildren(ctx context.Context, root *os.Root, name string, depth int) error {
	if depth > 128 {
		return errors.New("local point cleanup nesting exceeds its bound")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	directory, err := root.Open(name)
	if err != nil {
		return err
	}
	defer directory.Close()
	for {
		entries, readErr := directory.ReadDir(128)
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			child := filepath.Join(name, entry.Name())
			if entry.IsDir() {
				if err := removePointChildren(ctx, root, child, depth+1); err != nil {
					return err
				}
			}
			if err := root.Remove(child); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func writePointIntent(directory string, data []byte) error {
	if err := atomicfile.WriteFile(filepath.Join(directory, pointCleanupJournal), data, 0o600); err != nil {
		return err
	}
	return backupfs.SyncDirectory(directory)
}
func removePointIntent(directory string, root *os.Root) error {
	if err := root.Remove(pointCleanupJournal); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return backupfs.SyncDirectory(directory)
}

func requireUnusedPoint(directory, id string) error {
	var paths []string
	for _, name := range []string{pointName(id), pointGarbageName(id)} {
		for _, database := range []string{"state.db", "management.db"} {
			paths = append(paths, filepath.Join(directory, name, database))
		}
	}
	return sqlite.RequireClosed(paths...)
}
