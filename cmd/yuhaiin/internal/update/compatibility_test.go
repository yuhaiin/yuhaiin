//go:build linux || darwin || windows

package updatecmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUpdateHelperRejectsUnverifiedStagingAndCleansOnlyManagedPaths(t *testing.T) {
	for _, fault := range []string{"foreign_directory", "unowned_name", "update", "rollback"} {
		t.Run(fault, func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, "yuhaiin")
			stage := filepath.Join(directory, "yuhaiin-update-fixture")
			if fault == "foreign_directory" {
				stage = filepath.Join(t.TempDir(), "yuhaiin-update-fixture")
			}
			if fault == "unowned_name" {
				stage = filepath.Join(directory, "user-owned-file")
			}
			if fault == "rollback" {
				stage = filepath.Join(directory, ".yuhaiin-rollback-fixture")
			}
			for _, name := range []string{target, stage, stage + ".update.json"} {
				if err := os.WriteFile(name, []byte("protected; unverified"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			// No case can reach a service manager: metadata is intentionally invalid.
			if err := Install([]string{target, stage, directory}); err == nil {
				t.Fatal("unverified helper input accepted")
			}
			for _, name := range []string{stage, stage + ".update.json"} {
				_, err := os.Stat(name)
				if fault == "foreign_directory" || fault == "unowned_name" {
					if err != nil {
						t.Fatal("helper deleted an unowned file", err)
					}
				} else if !os.IsNotExist(err) {
					t.Fatal("failed helper retained its managed temporary file", err)
				}
			}
			actual, err := os.ReadFile(target)
			if err != nil || string(actual) != "protected; unverified" {
				t.Fatal("failed preflight changed installed executable", err)
			}
		})
	}
}
