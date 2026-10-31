package recovery

import (
	"encoding/json/v2"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

func TestWindowsRecoveryCrashWorker(t *testing.T) {
	directory := os.Getenv("YUH_RECOVERY_CRASH_DIRECTORY")
	if directory == "" {
		t.Skip("child process only")
	}
	data, err := os.ReadFile(filepath.Join(directory, "crash-plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var tx recoveryTransaction
	if err := json.Unmarshal(data, &tx); err != nil {
		t.Fatal(err)
	}
	err = activateRecoverySet(t.Context(), directory, &tx, func(phase string) error {
		if phase == os.Getenv("YUH_RECOVERY_CRASH_PHASE") {
			os.Exit(42) // Crash without running activation rollback or close defers.
		}
		return nil
	})
	t.Fatal("crash checkpoint was not reached", err)
}

func TestWindowsRecoveryProcessCrashRollback(t *testing.T) {
	for _, phase := range []string{"saved:a.key", "installed:a.key", "installed:new.key", "saved:b.key", "installed:b.key"} {
		t.Run(phase, func(t *testing.T) {
			directory, tx := recoveryTransactionFixture(t)
			data, err := json.Marshal(tx)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, "crash-plan.json"), data, 0o600); err != nil {
				t.Fatal(err)
			}
			child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestWindowsRecoveryCrashWorker$", "-test.count=1")
			child.Env = append(os.Environ(), "YUH_RECOVERY_CRASH_DIRECTORY="+directory, "YUH_RECOVERY_CRASH_PHASE="+phase)
			output, err := child.CombinedOutput()
			failure, ok := errors.AsType[*exec.ExitError](err)
			if !ok || failure.ExitCode() != 42 {
				t.Fatalf("worker did not exit at its crash checkpoint: %v\n%s", err, output)
			}
			pending, err := readRecoveryTransaction(directory)
			if err != nil || pending == nil || pending.Phase != "activating" {
				t.Fatal("crashed process lost its durable journal", err)
			}
			lock, err := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			if startup, err := PrepareStartup(directory, lock, tx.Runtime); err == nil || startup != nil {
				t.Fatal("crashed activation was admitted as a healthy startup")
			}
			assertRecoveryOriginalFiles(t, directory)
			if pending, err := readRecoveryTransaction(directory); err != nil || pending != nil {
				t.Fatal("recovered process retained an incomplete journal", err)
			}
		})
	}
}
