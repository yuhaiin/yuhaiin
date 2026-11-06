package maintenance

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestIndependentUpdateRecoveryAtEachDurableBoundary(t *testing.T) {
	source, target := binaries(t)
	for _, boundary := range []string{"prepared", "capturing", "backup_ready", "swapping_before", "swapping_after", "starting", "healthy", "foreign_target", "symlink_target"} {
		t.Run(boundary, func(t *testing.T) {
			directory, r, host, _ := deployment(t, source, target)
			if err := host.Stop(t.Context()); err != nil {
				t.Fatal(err)
			}
			phases := []string{"capturing", "backup_ready", "swapping", "starting", "healthy"}
			last := map[string]int{"prepared": -1, "capturing": 0, "backup_ready": 1, "swapping_before": 2, "swapping_after": 2, "starting": 3, "healthy": 4, "foreign_target": 2, "symlink_target": 2}[boundary]
			for _, phase := range phases[:last+1] {
				if err := SetPhase(t.Context(), directory, r.ID, phase, ""); err != nil {
					t.Fatal(err)
				}
			}
			if last >= 2 && boundary != "swapping_before" {
				if err := swapExecutable(r); err != nil {
					t.Fatal(err)
				}
			}
			if boundary == "foreign_target" {
				if err := os.WriteFile(r.TargetPath, []byte("operator replacement"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			sentinel := filepath.Join(t.TempDir(), "operator-file")
			if boundary == "symlink_target" {
				if err := os.Remove(r.TargetPath); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(sentinel, []byte("operator replacement"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(sentinel, r.TargetPath); err != nil {
					t.Fatal(err)
				}
			}
			err := Recover(t.Context(), directory, r.ID, host)
			current, readErr := Read(directory)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if boundary == "foreign_target" || boundary == "symlink_target" {
				if err == nil || host.starts != 0 || current.Phase != "swapping" {
					t.Fatal("unknown executable was overwritten or started", err, host.starts)
				}
				data, err := os.ReadFile(r.TargetPath)
				if err != nil || string(data) != "operator replacement" {
					t.Fatal("operator file changed", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if last >= 3 {
				if current.Phase != "manual_recovery" || host.starts != 0 {
					t.Fatal("possibly migrated stores restarted with old binary", current.Phase, host.starts)
				}
				if err := verify(t.Context(), r.TargetPath, r.Target); err != nil {
					t.Fatal(err)
				}
			} else {
				if current.Phase != "failed" || host.starts != 1 {
					t.Fatal("source recovery did not resume", current.Phase, host.starts)
				}
				if err := verify(t.Context(), r.TargetPath, r.Source); err != nil {
					t.Fatal(err)
				}
			}
			if err := Recover(t.Context(), directory, r.ID, host); err != nil {
				t.Fatal("recovery is not idempotent", err)
			}
			if _, err := os.Lstat(r.StagedPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("independent recovery left staged binary", err)
			}
		})
	}
}

func TestIndependentRecoveryRetriesInterruptedServiceAction(t *testing.T) {
	source, target := binaries(t)
	for _, tc := range []struct{ name, phase, code, final string }{
		{"source_restart_once", "failed", sourceRestartPending, "preparation_failed_source_preserved"},
		{"target_stop_once", "manual_recovery", targetStopPending, "startup_failed_restore_point_required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory, r, host, _ := deployment(t, source, target)
			host.fault = tc.name
			if err := host.Stop(t.Context()); err != nil {
				t.Fatal(err)
			}
			if tc.phase == "manual_recovery" {
				for _, phase := range []string{"capturing", "backup_ready", "swapping"} {
					if err := SetPhase(t.Context(), directory, r.ID, phase, ""); err != nil {
						t.Fatal(err)
					}
				}
				if err := swapExecutable(r); err != nil {
					t.Fatal(err)
				}
				if err := SetPhase(t.Context(), directory, r.ID, "starting", ""); err != nil {
					t.Fatal(err)
				}
			}
			if err := Recover(t.Context(), directory, r.ID, host); err == nil {
				t.Fatal("service action failure was swallowed")
			}
			current, err := Read(directory)
			if err != nil || current.Phase != tc.phase || current.ErrorCode != tc.code {
				t.Fatal("pending service action was lost", current, err)
			}
			if err := Recover(t.Context(), directory, r.ID, host); err != nil {
				t.Fatal(err)
			}
			current, err = Read(directory)
			if err != nil || current.Phase != tc.phase || current.ErrorCode != tc.final {
				t.Fatal("service action was not completed", current, err)
			}
			if tc.phase == "failed" && host.starts != 2 {
				t.Fatal("source restart was not retried")
			}
			if tc.phase == "manual_recovery" && (host.starts != 0 || host.stops != 3) {
				t.Fatal("target stop was not retried safely")
			}
		})
	}
}
