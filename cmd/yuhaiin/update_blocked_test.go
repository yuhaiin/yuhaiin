//go:build linux || darwin

package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/update/compatibility"
	updatemaintenance "github.com/Asutorufa/yuhaiin/pkg/update/maintenance"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
	"uuid"
)

// A terminal update refusal used to exit, so launchd KeepAlive restarted the
// service every ThrottleInterval with the same error. The real startup must now
// stay up without opening stores, release the lifecycle lock for update-adopt,
// and exit only after the journal/adoption/executable changes.
func TestBlockedUpdateStartupWaitsInsteadOfRestartLoop(t *testing.T) {
	for _, phase := range []string{"failed", "manual_recovery"} {
		t.Run(phase, func(t *testing.T) {
			directory := t.TempDir()
			binaries := t.TempDir()
			describe := func(name string) compatibility.Manifest {
				path := filepath.Join(binaries, name)
				if err := os.WriteFile(path, []byte(name+" executable"), 0700); err != nil {
					t.Fatal(err)
				}
				m, err := compatibility.Describe(t.Context(), path, runtime.GOOS, runtime.GOARCH)
				if err != nil {
					t.Fatal(err)
				}
				return m
			}
			record := updatemaintenance.Record{ID: uuid.New().String(), Source: describe("yuhaiin"), Target: describe("yuhaiin-update-target"),
				TargetPath: filepath.Join(binaries, "yuhaiin"), StagedPath: filepath.Join(binaries, "yuhaiin-update-target"), AllowNoPoint: true}
			if err := updatemaintenance.Begin(t.Context(), directory, record); err != nil {
				t.Fatal(err)
			}
			path := []string{"failed"}
			code := "preparation_failed_source_preserved"
			if phase == "manual_recovery" {
				path, code = []string{"capturing", "backup_ready", "swapping", "starting", "manual_recovery"}, "startup_failed_no_recovery_point"
			}
			for _, next := range path {
				if err := updatemaintenance.SetPhase(t.Context(), directory, record.ID, next, code); err != nil {
					t.Fatal(err)
				}
			}
			journal, err := os.ReadFile(filepath.Join(directory, ".update-operation.json"))
			if err != nil {
				t.Fatal(err)
			}
			previous := blockedStartupPoll
			blockedStartupPoll = 20 * time.Millisecond
			t.Cleanup(func() { blockedStartupPoll = previous })

			done := make(chan error, 1)
			go func() { done <- run([]string{"-path", directory, "-host", "127.0.0.1:0", "-https=false"}) }()
			select {
			case err := <-done:
				t.Fatal("blocked startup exited and would be restarted in a loop", err)
			case <-time.After(time.Second):
			}
			for _, file := range []string{"state.db", "management.db", "management-tls.pem"} {
				if _, err := os.Stat(filepath.Join(directory, file)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("blocked startup opened deployment data", file)
				}
			}
			lifecycle, err := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
			if err != nil {
				t.Fatal("blocked startup kept the lifecycle owner; offline recovery cannot run", err)
			}
			_ = lifecycle.Close()
			after, err := os.ReadFile(filepath.Join(directory, ".update-operation.json"))
			if err != nil || string(after) != string(journal) {
				t.Fatal("blocked startup changed or removed the failure record", err)
			}
			// An operator action (here an adoption file write) ends the wait so a
			// fresh process re-evaluates; validity is decided by that process.
			if err := os.WriteFile(filepath.Join(directory, ".update-adoption.json"), []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if !errors.Is(err, errBlockedStartupChanged) {
					t.Fatal("changed state did not request re-evaluation", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("changed state was not observed")
			}
		})
	}
}
