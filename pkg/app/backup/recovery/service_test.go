package recovery

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

type importServiceTest struct{ stop, start func(context.Context) error }

func (s importServiceTest) Stop(ctx context.Context) error  { return s.stop(ctx) }
func (s importServiceTest) Start(ctx context.Context) error { return s.start(ctx) }

func admitImportFixture(t *testing.T, directory string, item backupstore.RecoveryImportRecord, request contractrecovery.ImportActivateRequest) {
	t.Helper()
	db, err := sqlite.Open(t.Context(), filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	owner := backupstore.New(db.DB())
	item.State = "uploading"
	if err := owner.AddRecoveryImport(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	item.State = "previewed"
	if err := owner.SaveRecoveryImport(t.Context(), item, "uploading"); err != nil {
		t.Fatal(err)
	}
	item.State, item.Activation = "activating", new(request)
	if err := owner.AdmitRecoveryImport(t.Context(), item); err != nil {
		t.Fatal(err)
	}
}

func completeImportStartup(t *testing.T, directory string, abort bool) error {
	t.Helper()
	lock, err := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	tx, err := readRecoveryTransaction(directory)
	if err != nil || tx == nil {
		return err
	}
	startup, err := PrepareStartup(directory, lock, tx.Runtime)
	if err != nil {
		return err
	}
	if abort {
		return startup.Abort()
	}
	db, err := sqlite.Open(t.Context(), filepath.Join(directory, "state.db"))
	if err != nil {
		return err
	}
	if err := errors.Join(db.DB().PingContext(t.Context()), db.Close()); err != nil {
		return err
	}
	return startup.Complete()
}

func TestRestoreImportWaitsForActualCommitAndCleansPlaintext(t *testing.T) {
	source := newPreparedImportSource(t)
	for _, mode := range []string{"original", "clone"} {
		t.Run(mode, func(t *testing.T) {
			directory, item, request, _ := source.prepare(t, mode, false)
			admitImportFixture(t, directory, item, request)
			stops, starts := 0, 0
			service := importServiceTest{stop: func(context.Context) error { stops++; return nil }, start: func(context.Context) error { starts++; return completeImportStartup(t, directory, false) }}
			if err := RestoreImport(t.Context(), directory, item.ID, service); err != nil {
				t.Fatal(err)
			}
			result, err := RestoreStatus(t.Context(), directory)
			if err != nil || result.Result == nil || result.Result.State != "committed" || result.Result.TransactionID != item.PreviewID || stops != 1 || starts != 1 {
				t.Fatal("service manager start was mistaken for a committed restore", err, stops, starts)
			}
			if _, err := os.Lstat(filepath.Join(directory, ".recovery-imports", item.ID)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("committed restore retained plaintext/ciphertext staging", err)
			}
			if err := RestartImportService(t.Context(), directory, item.ID, service); err != nil {
				t.Fatal("normal ExecStopPost could not preserve a committed deployment", err)
			}
			current, err := RestoreStatus(t.Context(), directory)
			if err != nil || current.Result.State != "committed" {
				t.Fatal("crash fallback rolled back a committed deployment", err)
			}
		})
	}
}

func TestRestoreImportFailureRestartsOriginalAndRetainsOnlyCiphertext(t *testing.T) {
	source := newPreparedImportSource(t)
	for _, fault := range []string{"stop", "start", "abort", "staging"} {
		t.Run(fault, func(t *testing.T) {
			directory, item, request, _ := source.prepare(t, "clone", false)
			admitImportFixture(t, directory, item, request)
			if fault == "staging" {
				if err := os.WriteFile(filepath.Join(directory, item.Stage, "site.key"), []byte("changed after preview"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			stops, starts := 0, 0
			service := importServiceTest{stop: func(context.Context) error {
				stops++
				if fault == "stop" && stops == 1 {
					return errors.New("fixture stop failure")
				}
				return nil
			}, start: func(context.Context) error {
				starts++
				if starts == 1 && (fault == "start" || fault == "abort") {
					if fault == "abort" {
						if err := completeImportStartup(t, directory, true); err != nil {
							return err
						}
					}
					return errors.New("fixture restored listener failure")
				}
				return nil
			}}
			if err := RestoreImport(t.Context(), directory, item.ID, service); err == nil {
				t.Fatal("failed restore was reported as committed")
			}
			if starts < 1 {
				t.Fatal("original service was not restarted")
			}
			id, err := sqlite.RecoveryInstanceID(t.Context(), filepath.Join(directory, "state.db"), false)
			if err != nil || id != item.Preview.TargetInstanceID {
				t.Fatal("failed restore lost the original identity", err)
			}
			db, err := sqlite.Open(t.Context(), filepath.Join(directory, "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			current, err := backupstore.New(db.DB()).RecoveryImport(t.Context(), item.ID)
			if err != nil || current.State != "uploaded" || current.Plan != "" || current.Stage != "" || current.Preview != nil || current.Activation != nil || current.ErrorCode != "activation_failed" {
				t.Fatal("failed admission retained plaintext plan or lacked retry state", err)
			}
			if _, err := os.Lstat(filepath.Join(directory, item.Stage)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed restore retained plaintext staging", err)
			}
			if _, err := os.Stat(filepath.Join(directory, ".recovery-imports", item.ID, "archive.yhb")); err != nil {
				t.Fatal("failed restore lost retry ciphertext", err)
			}
		})
	}
}

func TestRestoreImportStartupTimeoutUsesBoundedClockAndRollback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		directory, item, request, _ := preparedImportFixture(t, "original", false)
		admitImportFixture(t, directory, item, request)
		stops, starts := 0, 0
		service := importServiceTest{stop: func(context.Context) error { stops++; return nil }, start: func(context.Context) error { starts++; return nil }}
		if err := RestoreImport(t.Context(), directory, item.ID, service); err == nil {
			t.Fatal("uncommitted startup was accepted")
		}
		result, err := LastResult(directory)
		if err != nil || result == nil || result.State != "rolled_back" || stops != 2 || starts != 2 {
			t.Fatal("startup deadline failed to restore/restart original", err, stops, starts)
		}
	})
}

func TestRestoreImportCrashFallbackOwnsOnlyItsAdmittedTransaction(t *testing.T) {
	source := newPreparedImportSource(t)
	for _, phase := range []string{"admitted", "activated"} {
		t.Run(phase, func(t *testing.T) {
			directory, item, request, _ := source.prepare(t, "clone", false)
			admitImportFixture(t, directory, item, request)
			item.Activation = new(request)
			if phase == "activated" {
				if _, err := ActivateImport(t.Context(), directory, item, request); err != nil {
					t.Fatal(err)
				}
			}
			starts := 0
			service := importServiceTest{stop: func(context.Context) error { return nil }, start: func(context.Context) error { starts++; return nil }}
			if err := RestartImportService(t.Context(), directory, item.ID, service); err != nil || starts != 1 {
				t.Fatal("crashed helper did not recover original service", err, starts)
			}
			actual, err := sqlite.RecoveryInstanceID(t.Context(), filepath.Join(directory, "state.db"), false)
			if err != nil || actual != item.Preview.TargetInstanceID {
				t.Fatal("crash fallback lost original identity", err)
			}
			if err := RestartImportService(t.Context(), directory, item.ID, service); err != nil || starts != 1 {
				t.Fatal("retired admission restarted an unrelated service", err, starts)
			}
		})
	}
}

func TestRestoreImportCleanupFailureCannotPreventSafeServiceRestart(t *testing.T) {
	source := newPreparedImportSource(t)
	for _, commit := range []bool{true, false} {
		t.Run(map[bool]string{true: "committed", false: "rolled_back"}[commit], func(t *testing.T) {
			directory, item, request, _ := source.prepare(t, "clone", false)
			admitImportFixture(t, directory, item, request)
			starts, stops := 0, 0
			service := importServiceTest{stop: func(context.Context) error { stops++; return nil }, start: func(context.Context) error {
				starts++
				if starts != 1 {
					return nil
				}
				if err := completeImportStartup(t, directory, !commit); err != nil {
					return err
				}
				// Corrupt only the staging namespace after file recovery is authoritative.
				// This works for both privileged and unprivileged tests without chmod tricks.
				path := filepath.Join(directory, ".recovery-imports")
				if err := os.Rename(path, filepath.Join(directory, ".retained-imports")); err != nil {
					return err
				}
				if err := os.WriteFile(path, []byte("fixture blocks cleanup"), 0600); err != nil {
					return err
				}
				if !commit {
					return errors.New("fixture restored startup failed")
				}
				return nil
			}}
			if err := RestoreImport(t.Context(), directory, item.ID, service); err == nil {
				t.Fatal("cleanup failure was hidden")
			}
			if starts < 2 {
				t.Fatal("cleanup failure prevented restarting a safe deployment", starts)
			}
			result, err := LastResult(directory)
			expected := "rolled_back"
			if commit {
				expected = "committed"
			}
			if err != nil || result == nil || result.State != expected {
				t.Fatal("cleanup changed the authoritative file outcome", err)
			}
			if commit && stops != 1 {
				t.Fatal("cleanup failure stopped a committed healthy deployment", stops)
			}
			if !commit {
				db, err := sqlite.Open(t.Context(), filepath.Join(directory, "state.db"))
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				record, err := backupstore.New(db.DB()).RecoveryImport(t.Context(), item.ID)
				if err != nil || record.State != "failed" || record.Stage == "" || record.Plan == "" || record.ErrorCode != "cleanup_failed" {
					t.Fatal("cleanup failure lost ownership or retained destructive admission", err)
				}
			}
		})
	}
}

func TestUpdateGuardSeesAdmittedRestoreInLiveWAL(t *testing.T) {
	directory, item, request, live := preparedImportFixture(t, "original", true)
	owner := backupstore.New(live.DB())
	item.State = "uploading"
	if err := owner.AddRecoveryImport(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	item.State = "previewed"
	if err := owner.SaveRecoveryImport(t.Context(), item, "uploading"); err != nil {
		t.Fatal(err)
	}
	item.State, item.Activation = "activating", new(request)
	if err := owner.AdmitRecoveryImport(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	if err := GuardMaintenance(directory); err != nil {
		t.Fatal("fixture unexpectedly has a file transaction", err)
	}
	if err := GuardServiceMaintenance(t.Context(), directory); !errors.Is(err, contract.ErrBusy) {
		t.Fatal("binary update missed an admission in the active WAL", err)
	}
	item.State, item.Activation = "uploaded", nil
	if err := owner.SaveRecoveryImport(t.Context(), item, "activating"); err != nil {
		t.Fatal(err)
	}
	if err := GuardServiceMaintenance(t.Context(), directory); err != nil {
		t.Fatal("retired admission kept updates blocked", err)
	}
}
