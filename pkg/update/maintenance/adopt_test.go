package maintenance

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

func manualBinary(t testing.TB) string {
	t.Helper()
	directory := t.TempDir()
	source := filepath.Join(directory, "manual.go")
	if err := os.WriteFile(source, []byte("package main\nimport \"fmt\"\nfunc main(){fmt.Println(\"manual\")}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(directory, "manual")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", executable, source)
	build.Env = append(os.Environ(), "GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH, "GOAMD64=v1", "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fixture: %v: %s", err, output)
	}
	return executable
}

// preparationFailure runs the real coordinator until source history
// preservation fails, leaving failed/preparation_failed_source_preserved.
func preparationFailure(t *testing.T, source, target string) (string, Record) {
	t.Helper()
	directory, r, host, _ := deployment(t, source, target)
	host.fault = "preserve"
	if err := Run(t.Context(), directory, r.ID, host); err == nil {
		t.Fatal("preparation fault did not fail")
	}
	current, err := Read(directory)
	if err != nil || current.Phase != "failed" || current.ErrorCode != "preparation_failed_source_preserved" {
		t.Fatal("expected a preserved-source preparation failure", err, current)
	}
	if err := host.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	return directory, *current
}

func replaceInstalled(t *testing.T, path, with string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	copyExecutable(t, with, path)
}

// evidence captures the journal bytes and the recovery-archive inventory, which
// adoption and refused startups must never rewrite or remove.
func evidence(t *testing.T, directory string) string {
	t.Helper()
	journal, err := os.ReadFile(filepath.Join(directory, journalName))
	if err != nil {
		t.Fatal(err)
	}
	result := string(journal)
	entries, err := os.ReadDir(filepath.Join(directory, ".recovery-archives"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		result += fmt.Sprintf("\n%s:%d", entry.Name(), info.Size())
	}
	return result
}

func adopt(ctx context.Context, directory, executable string, dryRun bool) (*Adoption, error) {
	return Adopt(ctx, directory, AdoptOptions{Executable: executable, Platform: runtime.GOOS, Architecture: runtime.GOARCH, DryRun: dryRun})
}

// requireBlocked returns the refusal's next steps; returning the error value
// itself would make every call site an unchecked error return.
func requireBlocked(t *testing.T, err error, executable string) []string {
	t.Helper()
	blocked, ok := IsStartupBlocked(err)
	if !ok {
		t.Fatalf("startup was not refused as blocked: %v", err)
	}
	if blocked.Executable != executable || len(blocked.NextSteps) == 0 {
		t.Fatalf("blocked startup classified %q, want %q (%v)", blocked.Executable, executable, blocked.NextSteps)
	}
	return blocked.NextSteps
}

func TestPreparationFailureStartupByInstalledExecutable(t *testing.T) {
	source, target := binaries(t)
	manual := manualBinary(t)

	t.Run("recorded_source", func(t *testing.T) {
		directory, r := preparationFailure(t, source, target)
		before := evidence(t, directory)
		startup, err := PrepareStartup(t.Context(), directory, r.TargetPath, "", "")
		if err != nil || startup != nil {
			t.Fatal("preserved source was not admitted", err)
		}
		if _, err := adopt(t.Context(), directory, r.TargetPath, false); err == nil || !strings.Contains(err.Error(), "recorded source executable is installed") {
			t.Fatal("source was adopted instead of started directly", err)
		}
		if evidence(t, directory) != before {
			t.Fatal("journal or recovery archives changed")
		}
	})

	t.Run("recorded_target", func(t *testing.T) {
		directory, r := preparationFailure(t, source, target)
		before := evidence(t, directory)
		replaceInstalled(t, r.TargetPath, target)
		_, err := PrepareStartup(t.Context(), directory, r.TargetPath, "", "")
		requireBlocked(t, err, "recorded_target")
		current, readErr := Read(directory)
		if readErr != nil || current.Phase != "failed" {
			t.Fatal("recorded target was treated as a completed update", readErr, current.Phase)
		}
		if evidence(t, directory) != before {
			t.Fatal("journal or recovery archives changed")
		}
	})

	t.Run("verified_manual_executable", func(t *testing.T) {
		directory, r := preparationFailure(t, source, target)
		before := evidence(t, directory)
		replaceInstalled(t, r.TargetPath, manual)
		_, err := PrepareStartup(t.Context(), directory, r.TargetPath, "", "")
		steps := requireBlocked(t, err, "unrecorded")
		if !slices.ContainsFunc(steps, func(step string) bool { return strings.Contains(step, "update-adopt") }) {
			t.Fatal("blocked startup did not name the adoption command", steps)
		}
		if _, err := adopt(t.Context(), directory, manual, false); err == nil || !strings.Contains(err.Error(), "from the installed executable") {
			t.Fatal("an executable other than the installed image adopted itself", err)
		}
		lifecycle, err := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := adopt(t.Context(), directory, r.TargetPath, false); err == nil || !strings.Contains(err.Error(), "stop it before adopting") {
			t.Fatal("adoption ignored a running database owner", err)
		}
		_ = lifecycle.Close()
		if a, err := adopt(t.Context(), directory, r.TargetPath, true); err != nil || a.Compatibility.State != "compatible" {
			t.Fatal("dry run did not verify the executable", err)
		}
		if a, err := ReadAdoption(directory); err != nil || a != nil {
			t.Fatal("dry run recorded an adoption", err)
		}
		a, err := adopt(t.Context(), directory, r.TargetPath, false)
		if err != nil {
			t.Fatal(err)
		}
		if a.OperationID != r.ID || a.Executable.SHA256 == r.SourceSHA256 || a.Executable.SHA256 == r.TargetSHA256 {
			t.Fatal("adoption is not bound to the operation and installed bytes")
		}
		startup, err := PrepareStartup(t.Context(), directory, r.TargetPath, "", "")
		if err != nil || startup != nil {
			t.Fatal("adopted executable was not admitted", err)
		}
		current, err := Read(directory)
		if err != nil || current.Phase != "failed" || current.ErrorCode != r.ErrorCode {
			t.Fatal("adoption rewrote the failure record", err, current)
		}
		if evidence(t, directory) != before {
			t.Fatal("journal or recovery archives changed")
		}
		if _, err := ActiveBackup(directory); err != nil {
			t.Fatal(err)
		}
		// The adoption covers exact bytes only. A later replacement is refused.
		replaceInstalled(t, r.TargetPath, target)
		_, err = PrepareStartup(t.Context(), directory, r.TargetPath, "", "")
		requireBlocked(t, err, "recorded_target")
		// Returning to the recorded source never needs the adoption.
		replaceInstalled(t, r.TargetPath, source)
		if _, err := PrepareStartup(t.Context(), directory, r.TargetPath, "", ""); err != nil {
			t.Fatal("source rejected after an adoption", err)
		}
	})

	t.Run("unknown_compatibility", func(t *testing.T) {
		directory, r := preparationFailure(t, source, target)
		replaceInstalled(t, r.TargetPath, manual)
		// A future migration this binary does not know: a schema it cannot prove safe.
		db, err := sqlite.Open(t.Context(), filepath.Join(directory, "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = db.DB().ExecContext(t.Context(), "INSERT INTO migrate(version,name,applied_at) VALUES (100000,'future_migration',0)")
		_ = db.Close()
		if err != nil {
			t.Fatal(err)
		}
		before := evidence(t, directory)
		if _, err := adopt(t.Context(), directory, r.TargetPath, false); err == nil || !strings.Contains(err.Error(), "cannot open this deployment") {
			t.Fatal("executable of unknown schema compatibility was adopted", err)
		}
		if a, err := ReadAdoption(directory); err != nil || a != nil {
			t.Fatal("refused adoption left a record", err)
		}
		_, err = PrepareStartup(t.Context(), directory, r.TargetPath, "", "")
		requireBlocked(t, err, "unrecorded")
		if evidence(t, directory) != before {
			t.Fatal("journal or recovery archives changed")
		}
	})

	t.Run("migration_required", func(t *testing.T) {
		directory, r := preparationFailure(t, source, target)
		replaceInstalled(t, r.TargetPath, manual)
		// Present the live database as one known migration behind this binary.
		db, err := sqlite.Open(t.Context(), filepath.Join(directory, "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = db.DB().ExecContext(t.Context(), "DELETE FROM migrate WHERE version=(SELECT max(version) FROM migrate); UPDATE metadata SET value=(SELECT CAST(max(version) AS TEXT) FROM migrate) WHERE key='schema_version'")
		_ = db.Close()
		if err != nil {
			t.Fatal(err)
		}
		before := evidence(t, directory)
		if _, err := adopt(t.Context(), directory, r.TargetPath, false); err == nil || !strings.Contains(err.Error(), "would migrate the databases") {
			t.Fatal("a migrating executable was adopted without a recovery point", err)
		}
		if a, err := ReadAdoption(directory); err != nil || a != nil {
			t.Fatal("refused adoption left a record", err)
		}
		if evidence(t, directory) != before {
			t.Fatal("journal or recovery archives changed")
		}
	})

	t.Run("adoption_after_schema_change", func(t *testing.T) {
		directory, r := preparationFailure(t, source, target)
		replaceInstalled(t, r.TargetPath, manual)
		if _, err := adopt(t.Context(), directory, r.TargetPath, false); err != nil {
			t.Fatal(err)
		}
		db, err := sqlite.Open(t.Context(), filepath.Join(directory, "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = db.DB().ExecContext(t.Context(), "INSERT INTO migrate(version,name,applied_at) VALUES (100000,'future_migration',0)")
		_ = db.Close()
		if err != nil {
			t.Fatal(err)
		}
		_, err = PrepareStartup(t.Context(), directory, r.TargetPath, "", "")
		requireBlocked(t, err, "adopted")
	})
}

// Once the target may have opened stores, adoption is unavailable and the
// paired archive/source restoration remains the only startup path.
func TestAdoptionNeverWeakensPostSwapRecovery(t *testing.T) {
	source, target := binaries(t)
	manual := manualBinary(t)
	for _, phase := range []string{"starting", "healthy", "manual_recovery"} {
		t.Run(phase, func(t *testing.T) {
			directory, r, host, _ := deployment(t, source, target)
			if err := host.Stop(t.Context()); err != nil {
				t.Fatal(err)
			}
			for _, next := range []string{"capturing", "backup_ready", "swapping", "starting", "healthy", "manual_recovery"} {
				if next == "healthy" && phase == "manual_recovery" {
					continue
				}
				if err := SetPhase(t.Context(), directory, r.ID, next, ""); err != nil {
					t.Fatal(err)
				}
				if next == phase {
					break
				}
			}
			replaceInstalled(t, r.TargetPath, manual)
			before := evidence(t, directory)
			if _, err := adopt(t.Context(), directory, r.TargetPath, false); err == nil || !strings.Contains(err.Error(), "only available after a preparation failure") {
				t.Fatal("adoption accepted after the target may have started", err)
			}
			startup, err := PrepareStartup(t.Context(), directory, r.TargetPath, "", "")
			if err == nil || startup != nil {
				t.Fatal("unknown executable admitted", err)
			}
			_, blocked := IsStartupBlocked(err)
			if blocked != (phase == "manual_recovery") {
				t.Fatal("only terminal manual recovery may wait instead of failing under the helper", err)
			}
			replaceInstalled(t, r.TargetPath, source)
			if _, err := PrepareStartup(t.Context(), directory, r.TargetPath, "", ""); err == nil {
				t.Fatal("source binary started without the matching restored archive")
			}
			if job, err := ActiveBackup(directory); err != nil || job != r.BackupJobID {
				t.Fatal("unresolved operation released its recovery point", err)
			}
			if a, err := ReadAdoption(directory); err != nil || a != nil {
				t.Fatal("refused adoption left a record", err)
			}
			if evidence(t, directory) != before {
				t.Fatal("journal or recovery archives changed")
			}
		})
	}
}

func TestWaitStartupChangeObservesJournalAdoptionAndExecutable(t *testing.T) {
	for _, change := range []string{"journal", "adoption", "executable"} {
		t.Run(change, func(t *testing.T) {
			directory := t.TempDir()
			executable := filepath.Join(t.TempDir(), "yuhaiin")
			if err := os.WriteFile(filepath.Join(directory, journalName), []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(executable, []byte("old"), 0700); err != nil {
				t.Fatal(err)
			}
			quiet, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			if err := WaitStartupChange(quiet, directory, executable, 10*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("unchanged state ended the wait", err)
			}
			done := make(chan error, 1)
			go func() { done <- WaitStartupChange(t.Context(), directory, executable, 10*time.Millisecond) }()
			time.Sleep(50 * time.Millisecond)
			path := map[string]string{"journal": filepath.Join(directory, journalName), "adoption": filepath.Join(directory, adoptionName), "executable": executable}[change]
			if err := os.WriteFile(path+".new", []byte("replacement"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(path+".new", path); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("state change was not observed")
			}
		})
	}
}
