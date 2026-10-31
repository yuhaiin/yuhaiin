package recovery

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"uuid"

	"github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/backupfs"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

func requireRecoveryDurability(t *testing.T, directory string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		if err := backupfs.SyncDirectory(directory); err != nil {
			if os.Getenv("YUH_WINDOWS_RECOVERY_REQUIRE") == "1" {
				t.Fatal("Windows recovery durability qualification failed", err)
			}
			t.Skip("recovery requires elevated local NTFS volume access", err)
		}
	}
}

func recoveryTransactionFixture(t *testing.T) (string, *recoveryTransaction) {
	t.Helper()
	directory := t.TempDir()
	requireRecoveryDurability(t, directory)
	stage := ".recovery-stage-fixture"
	if err := os.Mkdir(filepath.Join(directory, stage), 0o700); err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string]string{"a.key": "old-a", "b.key": "old-b", stage + "/a.key": "new-a", stage + "/b.key": "new-b", stage + "/new.key": "new-only"} {
		if err := os.WriteFile(filepath.Join(directory, filepath.FromSlash(path)), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tx := &recoveryTransaction{Version: 1, ID: uuid.New().String(), BackupID: uuid.New().String(), InstanceID: uuid.New().String(), Phase: "activating", Stage: stage, CreatedAt: time.Now(),
		Runtime: contractrecovery.Runtime{ManagementTLS: "disabled", WorkingDirectory: directory},
		Moves:   []recoveryMove{{Path: "a.key", HadOriginal: true, Install: true}, {Path: "new.key", Install: true}, {Path: "b.key", HadOriginal: true, Install: true}}}
	return directory, tx
}

func assertRecoveryOriginalFiles(t *testing.T, directory string) {
	t.Helper()
	for path, want := range map[string]string{"a.key": "old-a", "b.key": "old-b"} {
		data, err := os.ReadFile(filepath.Join(directory, path))
		if err != nil || string(data) != want {
			t.Fatalf("original %s was not preserved: %q %v", path, data, err)
		}
	}
	if _, err := os.Stat(filepath.Join(directory, "new.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rollback retained a newly installed identity")
	}
}

func TestRecoveryTransactionRollsBackEveryFailedMove(t *testing.T) {
	for _, phase := range []string{"before:a.key", "saved:a.key", "installed:a.key", "saved:new.key", "installed:new.key", "saved:b.key", "installed:b.key"} {
		t.Run(phase, func(t *testing.T) {
			directory, tx := recoveryTransactionFixture(t)
			fault := errors.New("injected file-switch failure")
			err := activateRecoverySet(t.Context(), directory, tx, func(label string) error {
				if label == phase {
					return fault
				}
				return nil
			})
			if !errors.Is(err, fault) {
				t.Fatalf("fault not propagated: %v", err)
			}
			assertRecoveryOriginalFiles(t, directory)
			if tx, err := readRecoveryTransaction(directory); err != nil || tx != nil {
				t.Fatal("completed rollback retained an active journal", err)
			}
		})
	}
}

func TestRecoveryTransactionInterruptedMovesAreRecoveredBeforeStartup(t *testing.T) {
	for _, phase := range []string{"saved:a.key", "installed:a.key", "installed:new.key", "saved:b.key", "installed:b.key"} {
		t.Run(phase, func(t *testing.T) {
			directory, tx := recoveryTransactionFixture(t)
			func() {
				defer func() {
					if recover() == nil {
						t.Fatal("fault did not interrupt activation")
					}
				}()
				_ = activateRecoverySet(t.Context(), directory, tx, func(label string) error {
					if label == phase {
						panic("simulated process interruption")
					}
					return nil
				})
			}()
			pending, err := readRecoveryTransaction(directory)
			if err != nil || pending == nil || pending.Phase != "activating" {
				t.Fatal("crash journal was not persisted", err)
			}
			if err := GuardMaintenance(directory); err == nil {
				t.Fatal("partial activation admitted another writer")
			}
			lock, err := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			if startup, err := PrepareStartup(directory, lock, tx.Runtime); err == nil || startup != nil {
				t.Fatal("interrupted activation was admitted as a successful startup")
			}
			assertRecoveryOriginalFiles(t, directory)
		})
	}
}

func TestRecoveryTransactionStartupAttemptCommitAndAbort(t *testing.T) {
	for _, finish := range []string{"commit", "abort", "crash"} {
		t.Run(finish, func(t *testing.T) {
			directory, tx := recoveryTransactionFixture(t)
			if err := activateRecoverySet(t.Context(), directory, tx, nil); err != nil {
				t.Fatal(err)
			}
			if err := CheckStartup(directory, ""); err == nil {
				t.Fatal("uncontrolled embedded startup bypassed pending restore")
			}
			lock, err := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			wrong := tx.Runtime
			wrong.ManagementTLS = "self_signed"
			if startup, err := PrepareStartup(directory, lock, wrong); err == nil || startup != nil {
				t.Fatal("changed TLS mode bypassed restored startup inputs")
			}
			startup, err := PrepareStartup(directory, lock, tx.Runtime)
			if err != nil || startup == nil {
				t.Fatal(err)
			}
			if err := CheckStartup(directory, startup.ID()); err != nil {
				t.Fatal(err)
			}
			switch finish {
			case "commit":
				if err := startup.Complete(); err != nil {
					t.Fatal(err)
				}
				if err := CheckStartup(directory, ""); err != nil {
					t.Fatal(err)
				}
				if original, err := os.ReadFile(filepath.Join(directory, tx.point(), "a.key")); err != nil || string(original) != "old-a" {
					t.Fatal("successful activation lost its original recovery point")
				}
			case "abort":
				if err := startup.Abort(); err != nil {
					t.Fatal(err)
				}
				assertRecoveryOriginalFiles(t, directory)
			case "crash":
				if again, err := PrepareStartup(directory, lock, tx.Runtime); err == nil || again != nil {
					t.Fatal("interrupted startup was silently accepted")
				}
				assertRecoveryOriginalFiles(t, directory)
			}
		})
	}
}

func TestRecoveryTransactionCancellationAndPathGuards(t *testing.T) {
	directory, tx := recoveryTransactionFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := activateRecoverySet(ctx, directory, tx, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	assertRecoveryOriginalFiles(t, directory)
	for _, path := range []string{"../escape", ".configuration.lock", ".recovery-transaction.json", "state.db-wal"} {
		bad := *tx
		bad.Moves = []recoveryMove{{Path: path, Install: true}}
		if err := bad.validate(); err == nil {
			t.Fatalf("unsafe install path accepted: %s", path)
		}
	}
	for _, stage := range []string{"../.recovery-stage-escape", "other/.recovery-stage-escape", ".recovery-imports/not-a-uuid/.recovery-stage-escape", ".recovery-imports/../.recovery-stage-escape"} {
		bad := *tx
		bad.Stage = stage
		if err := bad.validate(); err == nil {
			t.Fatal("unsafe recovery staging location accepted", stage)
		}
	}
}

func TestRecoveryRollbackCanResumeAfterOriginalInodeWasRestored(t *testing.T) {
	directory, tx := recoveryTransactionFixture(t)
	if err := activateRecoverySet(t.Context(), directory, tx, nil); err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("rollback interruption was not reached")
			}
		}()
		_ = rollbackRecoverySetCheckpoint(directory, tx, func(label string) {
			if label == "restored:a.key" {
				panic("interrupted rollback")
			}
		})
	}()
	pending, err := readRecoveryTransaction(directory)
	if err != nil || pending == nil || pending.Phase != "rolling_back" {
		t.Fatal("rollback lost its durable phase", err)
	}
	if err := rollbackRecoverySet(directory, pending); err != nil {
		t.Fatal(err)
	}
	assertRecoveryOriginalFiles(t, directory)
}

func TestRecoveryRollbackRefusesCorruptOrMissingOriginal(t *testing.T) {
	for _, fault := range []string{"corrupt", "missing"} {
		t.Run(fault, func(t *testing.T) {
			directory, tx := recoveryTransactionFixture(t)
			if err := activateRecoverySet(t.Context(), directory, tx, nil); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, tx.point(), "a.key")
			if fault == "missing" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte("broken"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := rollbackRecoverySet(directory, tx); err == nil {
				t.Fatal("corrupt rollback material was reported as restored")
			}
			if err := CheckStartup(directory, ""); err == nil {
				t.Fatal("failed rollback admitted ordinary startup")
			}
		})
	}
}
