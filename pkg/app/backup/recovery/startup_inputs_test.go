package recovery

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"uuid"

	testfixture "github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/testfixture"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	backuparchive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

func TestRecoveryManagedStartupCommitRestartAndRollback(t *testing.T) {
	directory, tx := recoveryTransactionFixture(t)
	db, err := sqlite.Open(t.Context(), filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sqlite.BindRecoveryInstance(t.Context(), filepath.Join(directory, "state.db"), tx.InstanceID); err != nil {
		t.Fatal(err)
	}
	lifecycle, err := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer lifecycle.Close()
	flags := contract.RecoveryRuntime{ManagementAuth: true, ManagementTLS: "self_signed", WorkingDirectory: directory, ListenAddress: "127.0.0.1:1"}
	if got, adopted, err := ResolveStartupInputs(t.Context(), directory, lifecycle, flags); err != nil || adopted || got != flags {
		t.Fatal("ordinary startup stopped using host configuration", err)
	}
	tx.AdoptStartup = true
	tx.Runtime = contract.RecoveryRuntime{ManagementAuth: true, ManagementTLS: "files", CertificateFile: filepath.Join(directory, "a.key"), KeyFile: filepath.Join(directory, "b.key"), WorkingDirectory: directory, ListenAddress: "127.0.0.1:2"}
	if err := activateRecoverySet(t.Context(), directory, tx, nil); err != nil {
		t.Fatal(err)
	}
	assertBinding := func(want contract.RecoveryRuntime) {
		t.Helper()
		got, adopted, err := ResolveStartupInputs(t.Context(), directory, lifecycle, flags)
		if err != nil || !adopted || got != want {
			t.Fatal("restored startup inputs did not survive the transaction", err, got, want)
		}
	}
	assertBinding(tx.Runtime)
	wrong := tx.Runtime
	wrong.ListenAddress = flags.ListenAddress
	if startup, err := PrepareStartup(directory, lifecycle, wrong); err == nil || startup != nil {
		t.Fatal("changed listener bypassed managed startup checks")
	}
	startup, err := PrepareStartup(directory, lifecycle, tx.Runtime)
	if err != nil || startup == nil {
		t.Fatal(err)
	}
	if err := startup.Complete(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(directory, ".recovery-last-result.json")); err != nil {
		t.Fatal(err)
	}
	committedStatus, err := RestoreStatus(t.Context(), directory)
	if err != nil || committedStatus.Result == nil || committedStatus.Result.TransactionID != tx.ID || committedStatus.Result.State != "committed" {
		t.Fatal("committed journal lost precedence over unavailable history", err)
	}
	assertBinding(tx.Runtime)
	if _, err := PrepareStartup(directory, lifecycle, tx.Runtime); err != nil {
		t.Fatal(err)
	}
	assertBinding(tx.Runtime) // Now only the existing last-result record remains.

	previous, err := recoveryStartupBindingFor(t.Context(), directory)
	if err != nil || previous == nil {
		t.Fatal(err)
	}
	stage := ".recovery-stage-second"
	if err := os.Mkdir(filepath.Join(directory, stage), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, stage, "a.key"), []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	second := *tx
	second.ID, second.Stage, second.Phase = uuid.New().String(), stage, "activating"
	second.PreviousStartup = previous
	second.Runtime.ManagementTLS, second.Runtime.CertificateFile, second.Runtime.KeyFile = "self_signed", "", ""
	second.Moves = []recoveryMove{{Path: "a.key", HadOriginal: true, Install: true}}
	if err := activateRecoverySet(t.Context(), directory, &second, nil); err != nil {
		t.Fatal(err)
	}
	assertBinding(second.Runtime)
	secondStartup, err := PrepareStartup(directory, lifecycle, second.Runtime)
	if err != nil || secondStartup == nil {
		t.Fatal(err)
	}
	if _, err := RestoreStatus(t.Context(), directory); err == nil {
		t.Fatal("unverified startup advertised a previous successful restore")
	}
	if err := secondStartup.Abort(); err != nil {
		t.Fatal(err)
	}
	assertBinding(tx.Runtime)
	result, err := LastResult(directory)
	if err != nil || result == nil || result.State != "rolled_back" || !result.AdoptStartup || result.Runtime != tx.Runtime {
		t.Fatal("rollback reported the failed startup inputs as active", err)
	}
	status, err := RestoreStatus(t.Context(), directory)
	if err != nil || status.Result == nil || *status.Result != *result {
		t.Fatal("management reporter disagrees with durable restore result", err)
	}
	if got, err := os.ReadFile(filepath.Join(directory, "a.key")); err != nil || string(got) != "new-a" {
		t.Fatal("rollback did not restore the preceding committed file", err)
	}

	for _, fault := range []string{"foreign_instance", "foreign_directory", "corrupt", "oversize", "alias"} {
		t.Run(fault, func(t *testing.T) {
			name := filepath.Join(directory, ".recovery-last-result.json")
			original, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = os.Remove(name); _ = os.WriteFile(name, original, 0o600) }()
			switch fault {
			case "foreign_instance":
				copy := second
				copy.PreviousStartup = &recoveryStartupBinding{InstanceID: uuid.New().String(), Runtime: tx.Runtime}
				if err := saveRecoveryResult(directory, copy, "rolled_back"); err != nil {
					t.Fatal(err)
				}
			case "foreign_directory":
				copy := second
				other := *previous
				other.Runtime.WorkingDirectory = t.TempDir()
				copy.PreviousStartup = &other
				if err := saveRecoveryResult(directory, copy, "rolled_back"); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(name, []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := os.WriteFile(name, make([]byte, (64<<10)+1), 0o600); err != nil {
					t.Fatal(err)
				}
			case "alias":
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("a.key", name); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := ResolveStartupInputs(t.Context(), directory, lifecycle, flags); err == nil {
				t.Fatal("invalid managed startup silently used host flags")
			}
		})
	}
}

func TestRecoveryManagedRollbackRetainsJournalUntilStartupBindingCanBeSaved(t *testing.T) {
	directory, tx := recoveryTransactionFixture(t)
	tx.AdoptStartup = true
	if err := activateRecoverySet(t.Context(), directory, tx, nil); err != nil {
		t.Fatal(err)
	}
	// Model an unavailable metadata destination after the original inodes have
	// been put back. A completed rollback cannot lose its startup binding.
	blocked := filepath.Join(directory, ".recovery-last-result.json")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := rollbackRecoverySet(directory, tx); err == nil {
		t.Fatal("managed rollback ignored its unavailable startup metadata")
	}
	assertRecoveryOriginalFiles(t, directory)
	pending, err := readRecoveryTransaction(directory)
	if err != nil || pending == nil || pending.Phase != "rolling_back" {
		t.Fatal("failed startup-metadata publication lost its recoverable journal", err)
	}
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
	if err := rollbackRecoverySet(directory, pending); err != nil {
		t.Fatal("managed rollback could not resume", err)
	}
	if pending, err := readRecoveryTransaction(directory); err != nil || pending != nil {
		t.Fatal("successful resumed rollback retained its active journal", err)
	}
	result, err := LastResult(directory)
	if err != nil || result == nil || result.AdoptStartup || result.State != "rolled_back" {
		t.Fatal("rollback failed to restore ordinary host startup", err)
	}
}

func TestRecoveryManagedStartupDoesNotPreventRestoringConfirmedDamagedDatabase(t *testing.T) {
	archive, manifest, key := recoveryRestoreArchive(t)
	directory, _ := testfixture.Deployment(t)
	id, err := recoveryTargetID(t.Context(), directory)
	if err != nil {
		t.Fatal(err)
	}
	previous := recoveryTransaction{ID: uuid.New().String(), BackupID: uuid.New().String(), InstanceID: id, AdoptStartup: true,
		Runtime: contract.RecoveryRuntime{ManagementAuth: true, ManagementTLS: "self_signed", WorkingDirectory: directory}}
	if err := saveRecoveryResult(directory, previous, "committed"); err != nil {
		t.Fatal(err)
	}
	damaged := []byte("damaged configuration database")
	if err := os.WriteFile(filepath.Join(directory, "state.db"), damaged, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Restore(t.Context(), directory, bytes.NewReader(archive), backuparchive.Decryption{Identity: key.String()}, RestoreOptions{
		Mode: "original", ConfirmedMaintenance: true, ConfirmBackupID: manifest.ID, ConfirmSourceInstanceID: manifest.InstanceID,
		ConfirmTargetInstanceID: "unreadable", ConfirmSourceStopped: true, ConfirmCredentialRevival: true, AdoptStartup: true,
	})
	if err != nil || result.State != "awaiting_startup" {
		t.Fatal("startup policy prevented disaster recovery of a confirmed damaged target", err)
	}
	if restored, err := recoveryTargetID(t.Context(), directory); err != nil || restored != manifest.InstanceID {
		t.Fatal("damaged deployment was not replaced by the validated archive", err)
	}
	if err := Rollback(directory, result.TransactionID, true); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(directory, "state.db")); err != nil || !bytes.Equal(data, damaged) {
		t.Fatal("rollback lost the preceding damaged file", err)
	}
	lifecycle, err := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer lifecycle.Close()
	if _, _, err := ResolveStartupInputs(t.Context(), directory, lifecycle, contract.RecoveryRuntime{}); err == nil {
		t.Fatal("damaged original silently fell back to host startup settings")
	}
}
