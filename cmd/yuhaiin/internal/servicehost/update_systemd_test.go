//go:build linux

package servicehost

import (
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"uuid"

	"filippo.io/age"

	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	updatepkg "github.com/Asutorufa/yuhaiin/pkg/update"
	"github.com/Asutorufa/yuhaiin/pkg/update/compatibility"
	"github.com/Asutorufa/yuhaiin/pkg/update/maintenance"
)

// Only the disposable systemd runner may execute this test. The driver admits
// immutable registry/journal records directly; REST admission has separate tests.
// All stop/capture/swap/start/receipt/restore work runs in production executables.
func TestInstalledProtectedUpdate(t *testing.T) {
	if os.Getenv("YUHAIIN_RECOVERY_SYSTEMD_DRILL") != "1" {
		t.Skip("use scripts/bench/recovery-maintenance/run.py")
	}
	if (os.Geteuid() != 0) != drillUser() {
		t.Fatal("fixture user does not match the selected service manager")
	}
	if _, err := os.Stat("/run/systemd/container"); err != nil {
		t.Fatal("isolated systemd container required")
	}
	sourceSchema, err := sqlite.SupportedSchemaVersion("configuration")
	if err != nil {
		t.Fatal(err)
	}
	command := func(args ...string) error {
		out, err := drillSystemctl(t.Context(), args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("systemctl %v: %w: %s", args, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	pid := func(unit string) int {
		out, _ := drillSystemctl(t.Context(), "show", unit, "--property=MainPID", "--value").Output()
		v, _ := strconv.Atoi(strings.TrimSpace(string(out)))
		return v
	}
	copyFile := func(from, to string) {
		t.Helper()
		input, err := os.Open(from)
		if err != nil {
			t.Fatal(err)
		}
		defer input.Close()
		output, err := os.OpenFile(to, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0700)
		if err != nil {
			t.Fatal(err)
		}
		_, copyErr := io.Copy(output, input)
		closeErr := output.Close()
		if copyErr != nil || closeErr != nil {
			t.Fatal(copyErr, closeErr)
		}
	}
	wait := func(label string, ready func() bool) {
		t.Helper()
		deadline := time.Now().Add(100 * time.Second)
		for time.Now().Before(deadline) {
			if ready() {
				return
			}
			select {
			case <-t.Context().Done():
				t.Fatal(t.Context().Err())
			case <-time.After(100 * time.Millisecond):
			}
		}
		t.Fatal("timed out: " + label)
	}
	for _, scenario := range []string{"healthy_migration", "failed_readiness", "killed_startup"} {
		t.Run(scenario, func(t *testing.T) {
			_ = command("stop", "yuhaiin.service")
			directory := drillDataPath("data-update-" + scenario)
			if err := os.MkdirAll(filepath.Join(directory, "web"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, "web", "index.html"), []byte("update fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			executable := "/app/yuhaiin-update-" + scenario
			copyFile("/app/yuhaiin", executable)
			unit := fmt.Sprintf("[Unit]\nDescription=Isolated protected update fixture\n[Service]\nType=simple\nExecStart=%s run -path %s -https=true -host 127.0.0.1:50052 -eweb %s/web\nRestart=no\n", executable, directory, directory)
			if err := os.WriteFile(drillUnitPath(t), []byte(unit), 0600); err != nil {
				t.Fatal(err)
			}
			if err := command("daemon-reload"); err != nil {
				t.Fatal(err)
			}
			_ = command("reset-failed", "yuhaiin.service")
			if err := command("start", "yuhaiin.service"); err != nil {
				t.Fatal(err)
			}
			wait("source startup", func() bool { return pid("yuhaiin.service") > 0 && fileExists(filepath.Join(directory, "state.db")) })
			// Metadata-only access does not bootstrap or migrate target-owned stores.
			db, err := sql.Open(sqlite.DriverName(), "file:"+filepath.Join(directory, "state.db")+"?mode=rw")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			db.SetMaxOpenConns(1)
			if _, err := db.ExecContext(t.Context(), "PRAGMA busy_timeout=5000"); err != nil {
				t.Fatal(err)
			}
			owner := backupstore.New(db)
			wait("source inputs recorded", func() bool {
				value, err := backupstore.LoadRecoveryRuntime(t.Context(), db)
				return err == nil && value != nil
			})
			key, err := age.GenerateX25519Identity()
			if err != nil {
				t.Fatal(err)
			}
			policy, err := backupstore.NormalizeRecoveryPolicy(contractrecovery.Policy{Recipient: key.Recipient().String(), AllowMaintenance: true, IncludeHistory: true, TimeoutMinutes: 2})
			if err != nil {
				t.Fatal(err)
			}
			job := backupstore.RecoveryJob{ID: uuid.New().String(), CreatedAt: time.Now().UTC(), Target: "local", State: "queued", Policy: policy, IncludesHistory: true, UpdatePoint: true}
			if err := owner.EnqueueRecovery(t.Context(), job); err != nil {
				t.Fatal(err)
			}
			source, err := compatibility.Describe(t.Context(), executable, "linux", "amd64")
			if err != nil {
				t.Fatal(err)
			}
			input := "/app/update-healthy"
			if scenario == "failed_readiness" {
				input = "/app/update-failed"
			}
			stage := filepath.Join(filepath.Dir(executable), "yuhaiin-update-"+uuid.New().String())
			copyFile(input, stage)
			data, err := os.ReadFile(input + compatibility.Suffix)
			if err != nil {
				t.Fatal(err)
			}
			target, err := compatibility.Parse(data)
			if err != nil {
				t.Fatal(err)
			}
			id := uuid.New().String()
			r := maintenance.Record{ID: id, Source: source, Target: target, TargetPath: executable, StagedPath: stage, BackupJobID: job.ID, SourceVersion: "fixture-source"}
			if err := maintenance.Begin(t.Context(), directory, r); err != nil {
				t.Fatal(err)
			}
			barrier := filepath.Join(directory, "startup-barrier")
			if scenario == "killed_startup" {
				// Fence the real target's ExecStartPre, after the helper persisted starting.
				// This needs no production fault hook or timing-dependent process kill.
				unit += "ExecStartPre=/bin/sh -c 'touch " + barrier + "; while test -f " + barrier + "; do sleep 0.1; done'\n"
				if err := os.WriteFile(drillUnitPath(t), []byte(unit), 0600); err != nil {
					t.Fatal(err)
				}
				if err := command("daemon-reload"); err != nil {
					t.Fatal(err)
				}
			}
			supervisor := "yuhaiin-protected-update-" + id + ".service"
			restart := executable + " update-protected-recover " + directory + " " + id
			if err := SystemdRun(t.Context(), "--quiet", "--no-block", "--collect", "--unit="+strings.TrimSuffix(supervisor, ".service"), "--property=Type=exec", "--property=RuntimeMaxSec=180", "--property=ExecStopPost=:"+restart, executable, "update-protected-helper", directory, id); err != nil {
				t.Fatal(err)
			}
			if scenario == "killed_startup" {
				wait("target startup fence", func() bool { return fileExists(barrier) })
				if err := command("kill", "--kill-whom=main", "--signal=KILL", supervisor); err != nil {
					t.Fatal(err)
				}
			}
			var outcome *maintenance.Record
			wait("durable update outcome", func() bool {
				outcome, err = maintenance.Read(directory)
				return err == nil && outcome != nil && maintenance.Terminal(outcome.Phase)
			})
			if outcome.BackupID == "" || outcome.BackupJobID != job.ID {
				t.Fatal("update has no paired encrypted point")
			}
			if scenario == "healthy_migration" {
				if outcome.Phase != "completed" || outcome.ReadyPID != pid("yuhaiin.service") || outcome.ReadyPID == 0 {
					t.Fatal("update success has no matching installed-service receipt", outcome.Phase)
				}
			} else {
				if outcome.Phase != "manual_recovery" || pid("yuhaiin.service") != 0 {
					t.Fatal("ambiguous startup did not remain stopped", outcome.Phase)
				}
			}
			var version int
			if err := db.QueryRowContext(t.Context(), "SELECT CAST(value AS INTEGER) FROM metadata WHERE key='schema_version'").Scan(&version); err != nil {
				t.Fatal(err)
			}
			if scenario != "killed_startup" && version != sourceSchema+1 {
				t.Fatal("real migration did not persist before readiness outcome", version)
			}
			if scenario == "healthy_migration" {
				return
			}
			// The old executable must refuse startup before touching possibly migrated stores.
			premature := exec.CommandContext(t.Context(), "/app/yuhaiin", "run", "-path", directory, "-https=false", "-host", "127.0.0.1:0")
			if err := premature.Run(); err == nil {
				t.Fatal("source started before paired database recovery")
			}
			wait("independent helper cleanup", func() bool { return pid(supervisor) == 0 })
			// Restoration runs through the public offline CLI with the external key, not
			// through a direct database copy or a fake successful service start.
			identity := filepath.Join(directory, "external-test-identity")
			if err := os.WriteFile(identity, []byte(key.String()), 0600); err != nil {
				t.Fatal(err)
			}
			archive := filepath.Join(directory, ".recovery-archives", job.ID+".yhb")
			previewCmd := exec.CommandContext(t.Context(), "/app/yuhaiin", "recovery", "preview", "-path", directory, "-archive", archive, "-identity-file", identity, "-mode", "original")
			previewJSON, err := previewCmd.Output()
			if err != nil {
				t.Fatal("offline preview failed", err)
			}
			var preview contractrecovery.RestorePreview
			if err := json.Unmarshal(previewJSON, &preview); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			restore := exec.CommandContext(t.Context(), "/app/yuhaiin", "recovery", "restore", "-path", directory, "-archive", archive, "-identity-file", identity, "-mode", "original", "-maintenance", "-adopt-startup", "-confirm-backup", outcome.BackupID, "-confirm-source-instance", preview.Manifest.InstanceID, "-confirm-target-instance", preview.TargetInstanceID, "-source-stopped", "-restore-credentials")
			if err := restore.Run(); err != nil {
				t.Fatal("offline paired recovery failed", err)
			}
			// The verified source in normal binary history is the required partner.
			copyFile(filepath.Join(updatepkg.HistoryDirectory(directory), source.SHA256+".bin"), executable)
			if scenario == "killed_startup" {
				// The startup fence belongs only to the injected target attempt.
				unit = strings.Split(unit, "ExecStartPre=")[0]
				if err := os.WriteFile(drillUnitPath(t), []byte(unit), 0600); err != nil {
					t.Fatal(err)
				}
				if err := command("daemon-reload"); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(barrier); err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
			}
			_ = command("reset-failed", "yuhaiin.service")
			if err := command("start", "yuhaiin.service"); err != nil {
				t.Fatal(err)
			}
			wait("verified paired recovery startup", func() bool {
				record, err := maintenance.Read(directory)
				return err == nil && record != nil && record.Phase == "recovered" && pid("yuhaiin.service") > 0
			})
			read, err := sqlite.OpenSnapshotReader(t.Context(), filepath.Join(directory, "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer read.Close()
			if err := read.QueryRowContext(t.Context(), "SELECT CAST(value AS INTEGER) FROM metadata WHERE key='schema_version'").Scan(&version); err != nil || version != sourceSchema {
				t.Fatal("source schema not recovered", version, err)
			}
		})
	}
}
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
