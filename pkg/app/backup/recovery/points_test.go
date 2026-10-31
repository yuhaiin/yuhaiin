package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
	"uuid"

	testfixture "github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/testfixture"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	gatewaycontract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/store"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

func makeLocalPoint(t testing.TB, directory string, at time.Time, phase string) recoveryTransaction {
	t.Helper()
	id := uuid.New().String()
	data := []byte("private old state fixture")
	digest := sha256.Sum256(data)
	tx := recoveryTransaction{Version: 1, ID: id, BackupID: uuid.New().String(), InstanceID: uuid.New().String(), CreatedAt: at, Phase: phase, Stage: ".recovery-stage-fixture", Runtime: contract.Runtime{ManagementTLS: "disabled", WorkingDirectory: directory}, Moves: []recoveryMove{{Path: "state.db", HadOriginal: true, OriginalSHA256: hex.EncodeToString(digest[:])}}}
	if err := os.Mkdir(filepath.Join(directory, tx.point()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, tx.point(), "state.db"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := saveRecoveryPointRecord(directory, tx); err != nil {
		t.Fatal(err)
	}
	return tx
}
func requirePointPresent(t *testing.T, directory, id string, present bool) {
	t.Helper()
	_, err := os.Stat(filepath.Join(directory, pointName(id)))
	if present && err != nil || !present && !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unexpected point existence", id, present, err)
	}
}

func TestPointRetentionPinsCurrentLatestAndUnfinishedCopies(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("durable directory synchronization")
	}
	directory := t.TempDir()
	now := time.Now()
	newest := makeLocalPoint(t, directory, now.Add(-time.Hour), "committed")
	latest := makeLocalPoint(t, directory, now.Add(-30*24*time.Hour), "committed")
	pending := makeLocalPoint(t, directory, now.Add(-40*24*time.Hour), "checking")
	old := makeLocalPoint(t, directory, now.Add(-60*24*time.Hour), "committed")
	rolledBack := makeLocalPoint(t, directory, now.Add(-90*24*time.Hour), "rolled_back")
	orphan := makeLocalPoint(t, directory, now.Add(-100*24*time.Hour), "activating")
	if err := saveRecoveryTransaction(directory, pending); err != nil {
		t.Fatal(err)
	}
	if err := saveRecoveryResult(directory, latest, "committed"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "live.keep"), []byte("live state"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := PrunePoints(t.Context(), directory, contract.PointRetention{Enabled: true, KeepCount: 1, KeepDays: 1}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Deleted) != 2 || !slices.Contains(result.Deleted, old.ID) || !slices.Contains(result.Deleted, rolledBack.ID) {
		t.Fatal("wrong retention plan", result)
	}
	for _, tx := range []recoveryTransaction{newest, latest, pending, orphan} {
		requirePointPresent(t, directory, tx.ID, true)
	}
	live, err := os.ReadFile(filepath.Join(directory, "live.keep"))
	if err != nil || string(live) != "live state" {
		t.Fatal("cleanup touched live state", err)
	}
}

func TestPointRetentionDefaultsAgeCountAndResourceBound(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("durable directory synchronization")
	}
	directory := t.TempDir()
	now := time.Now()
	for index := range 40 {
		makeLocalPoint(t, directory, now.Add(-time.Duration(index+1)*time.Hour), "committed")
	}
	disabled, err := PrunePoints(t.Context(), directory, contract.PointRetention{}, true)
	if err != nil || len(disabled.Deleted) != 0 {
		t.Fatal("legacy default deleted data", disabled, err)
	}
	first, err := PrunePoints(t.Context(), directory, contract.PointRetention{Enabled: true, KeepCount: 1, KeepDays: 1}, true)
	if err != nil || len(first.Deleted) != maxPointCleanup {
		t.Fatal("cleanup batch is unbounded", first, err)
	}
	second, err := PrunePoints(t.Context(), directory, contract.PointRetention{Enabled: true, KeepCount: 1, KeepDays: 1}, true)
	if err != nil || len(second.Deleted) != 7 {
		t.Fatal("bounded cleanup did not finish later", second, err)
	}
	third, err := PrunePoints(t.Context(), directory, contract.PointRetention{Enabled: true, KeepCount: 1, KeepDays: 1}, true)
	if err != nil || len(third.Deleted) != 0 {
		t.Fatal("latest copy was lost", third, err)
	}
}

func TestPointCleanupResumesBeforeAndAfterRenameAndPartialRemoval(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("durable directory synchronization")
	}
	for _, boundary := range []string{"intent", "renamed", "metadata_removed", "directory_removed"} {
		t.Run(boundary, func(t *testing.T) {
			directory := t.TempDir()
			now := time.Now()
			newest := makeLocalPoint(t, directory, now.Add(-time.Hour), "committed")
			victim := makeLocalPoint(t, directory, now.Add(-48*time.Hour), "committed")
			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			record, err := readPointRecord(root, victim.ID)
			if err != nil {
				t.Fatal(err)
			}
			intent := pointCleanupIntent{Version: 1, ID: victim.ID, SHA256: record.digest}
			data, err := json.Marshal(intent)
			if err != nil {
				t.Fatal(err)
			}
			if err := writePointIntent(directory, data); err != nil {
				t.Fatal(err)
			}
			if boundary != "intent" {
				if err := root.Rename(victim.point(), pointGarbageName(victim.ID)); err != nil {
					t.Fatal(err)
				}
			}
			if boundary == "metadata_removed" {
				if err := root.Remove(filepath.Join(pointGarbageName(victim.ID), ".recovery-meta", "transaction.json")); err != nil {
					t.Fatal(err)
				}
			}
			if boundary == "directory_removed" {
				if err := os.RemoveAll(filepath.Join(directory, pointGarbageName(victim.ID))); err != nil {
					t.Fatal(err)
				}
			}
			cancelled, cancel := context.WithCancel(t.Context())
			cancel()
			if err := finishPointCleanup(cancelled, directory, root, intent); !errors.Is(err, context.Canceled) {
				t.Fatal("cancelled cleanup mutated data", err)
			}
			result, err := PrunePoints(t.Context(), directory, contract.PointRetention{Enabled: true, KeepCount: 1, KeepDays: 1}, true)
			if err != nil || !slices.Contains(result.Deleted, victim.ID) {
				t.Fatal("interrupted cleanup did not resume", result, err)
			}
			requirePointPresent(t, directory, newest.ID, true)
			if _, err := os.Lstat(filepath.Join(directory, pointCleanupJournal)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("completed cleanup retained journal", err)
			}
		})
	}
}

func TestPointRetentionRejectsSymlinksChangedMetadataAndActiveOwners(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("durable directory synchronization")
	}
	directory := t.TempDir()
	now := time.Now()
	makeLocalPoint(t, directory, now.Add(-time.Hour), "committed")
	victim := makeLocalPoint(t, directory, now.Add(-48*time.Hour), "committed")
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "keep")
	if err := os.WriteFile(sentinel, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, victim.point(), "outside")); err != nil {
		t.Fatal(err)
	}
	if _, err := PrunePoints(t.Context(), directory, contract.PointRetention{Enabled: true, KeepCount: 1, KeepDays: 1}, false); err == nil {
		t.Fatal("missing maintenance consent accepted")
	}
	owner, err := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PrunePoints(t.Context(), directory, contract.PointRetention{Enabled: true, KeepCount: 1, KeepDays: 1}, true); err == nil {
		t.Fatal("active deployment owner was ignored")
	}
	owner.Close()
	if _, err := PrunePoints(t.Context(), directory, contract.PointRetention{Enabled: true, KeepCount: 1, KeepDays: 1}, true); err != nil {
		t.Fatal(err)
	}
	if value, err := os.ReadFile(sentinel); err != nil || string(value) != "untouched" {
		t.Fatal("cleanup followed an outside symlink", err)
	}
	// A journal without a matching source digest cannot authorize unlinking it.
	changed := makeLocalPoint(t, directory, now.Add(-72*time.Hour), "committed")
	if err := writePointIntent(directory, []byte(`{"version":1,"id":"`+changed.ID+`","sha256":"`+strings.Repeat("0", 64)+`"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := PrunePoints(t.Context(), directory, contract.PointRetention{Enabled: true, KeepCount: 1, KeepDays: 1}, true); err == nil {
		t.Fatal("changed metadata was deleted")
	}
	requirePointPresent(t, directory, changed.ID, true)
}

func TestPointRetentionProtectsOpenSQLiteCopy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("durable directory synchronization")
	}
	directory := t.TempDir()
	now := time.Now()
	makeLocalPoint(t, directory, now.Add(-time.Hour), "committed")
	active := makeLocalPoint(t, directory, now.Add(-48*time.Hour), "committed")
	path := filepath.Join(directory, active.point(), "state.db")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	db, err := testfixture.OpenState(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	result, err := PrunePoints(t.Context(), directory, contract.PointRetention{Enabled: true, KeepCount: 1, KeepDays: 1}, true)
	if err != nil || len(result.Deleted) != 0 {
		t.Fatal("in-use SQLite copy was deleted", result, err)
	}
	requirePointPresent(t, directory, active.ID, true)
}

func TestPointRetentionPreservesConfiguredCertificateAliases(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("durable directory synchronization")
	}
	directory := t.TempDir()
	now := time.Now()
	makeLocalPoint(t, directory, now.Add(-time.Hour), "committed")
	referenced := makeLocalPoint(t, directory, now.Add(-48*time.Hour), "committed")
	alias := filepath.Join(directory, "old-site-key")
	if err := os.Symlink(filepath.Join(directory, referenced.point(), "state.db"), alias); err != nil {
		t.Fatal(err)
	}
	db, err := testfixture.OpenState(t.Context(), filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := backupstore.New(db.DB()).RecordRecoveryRuntime(t.Context(), contract.Runtime{ManagementTLS: "disabled", WorkingDirectory: directory}); err != nil {
		t.Fatal(err)
	}
	_, err = store.NewGatewayStore(db.DB()).Save(t.Context(), gatewaycontract.Config{Gateways: []gatewaycontract.Gateway{{ID: "alias-site", Name: "Alias site", Listen: "127.0.0.1:0", TLSMode: "terminate", CertificateFile: alias, KeyFile: alias}}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := PrunePoints(t.Context(), directory, contract.PointRetention{Enabled: true, KeepCount: 1, KeepDays: 1}, true)
	if err == nil {
		t.Fatal("offline cleanup ignored the active configuration DB", result)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	result, err = PrunePoints(t.Context(), directory, contract.PointRetention{Enabled: true, KeepCount: 1, KeepDays: 1}, true)
	if err != nil || len(result.Deleted) != 0 {
		t.Fatal("configured old certificate dependency was removed", result, err)
	}
	requirePointPresent(t, directory, referenced.ID, true)
}

func TestPointRetentionKeepsLatestCommittedCopyAfterRollback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("durable directory synchronization")
	}
	directory := t.TempDir()
	now := time.Now()
	rolled := makeLocalPoint(t, directory, now.Add(-time.Hour), "rolled_back")
	committed := makeLocalPoint(t, directory, now.Add(-48*time.Hour), "committed")
	result, err := PrunePoints(t.Context(), directory, contract.PointRetention{Enabled: true, KeepCount: 1, KeepDays: 1}, true)
	if err != nil || len(result.Deleted) != 0 {
		t.Fatal("latest committed copy was displaced by a rollback record", result, err)
	}
	requirePointPresent(t, directory, rolled.ID, true)
	requirePointPresent(t, directory, committed.ID, true)
}
