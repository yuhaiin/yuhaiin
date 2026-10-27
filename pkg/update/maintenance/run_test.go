package maintenance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"uuid"

	"filippo.io/age"
	"github.com/Asutorufa/yuhaiin/pkg/app/backup/recovery"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	backuparchive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
	"github.com/Asutorufa/yuhaiin/pkg/update/compatibility"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

type hostFixture struct {
	directory     string
	database      *sqlite.Store
	fault         string
	starts, stops int
	cancel        context.CancelFunc
}

func (h *hostFixture) Stop(context.Context) error {
	h.stops++
	if h.database != nil {
		err := h.database.Close()
		h.database = nil
		return err
	}
	return nil
}
func (h *hostFixture) ConfirmReady(context.Context, Record) error {
	if h.fault == "listener" {
		h.cancel()
		return errors.New("listener unavailable after receipt")
	}
	return nil
}
func (h *hostFixture) MainPID(context.Context) (int, error) { return os.Getpid(), nil }
func (h *hostFixture) Preserve(context.Context, Record) error {
	if h.fault == "preserve" {
		return errors.New("preserve failed")
	}
	return nil
}
func (h *hostFixture) Prune(context.Context, Record) error {
	if h.fault == "prune" {
		return errors.New("retention failed")
	}
	return nil
}
func (h *hostFixture) Start(ctx context.Context) error {
	h.starts++
	r, err := Read(h.directory)
	if err != nil {
		return err
	}
	startup, err := PrepareStartup(ctx, h.directory, r.TargetPath, "", "")
	if err != nil {
		return err
	}
	if r.Phase == "failed" {
		return nil
	}
	if h.fault == "startup" {
		db, err := sqlite.Open(ctx, filepath.Join(h.directory, "state.db"))
		if err != nil {
			return err
		}
		_, err = db.DB().ExecContext(ctx, "UPDATE metadata SET value='999' WHERE key='schema_version'; UPDATE metadata SET value='after-target-start' WHERE key='business_value'")
		_ = db.Close()
		if err != nil {
			return err
		}
		return errors.New("target migrated and failed before readiness")
	}
	if h.fault == "no_receipt" {
		h.cancel()
		return nil
	}
	return startup.Complete(ctx, "127.0.0.1:1", nil)
}
func binaries(t testing.TB) (string, string) {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("installed supervisor fixture uses Linux amd64")
	}
	directory := t.TempDir()
	result := []string{}
	for _, name := range []string{"source", "target"} {
		source := filepath.Join(directory, name+".go")
		if err := os.WriteFile(source, fmt.Appendf(nil, "package main\nimport \"fmt\"\nfunc main(){fmt.Println(%q)}\n", name), 0600); err != nil {
			t.Fatal(err)
		}
		executable := filepath.Join(directory, name)
		build := exec.CommandContext(t.Context(), "go", "build", "-o", executable, source)
		build.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "GOAMD64=v1", "CGO_ENABLED=0")
		if output, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build fixture: %v: %s", err, output)
		}
		result = append(result, executable)
	}
	return result[0], result[1]
}
func copyExecutable(t testing.TB, source, destination string) {
	t.Helper()
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(output, input)
	closeErr := output.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
}
func deployment(t testing.TB, source, target string) (string, Record, *hostFixture, *age.X25519Identity) {
	t.Helper()
	directory := t.TempDir()
	db, err := sqlite.Open(t.Context(), filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	host := &hostFixture{directory: directory, database: db}
	t.Cleanup(func() {
		if host.database != nil {
			_ = host.database.Close()
		}
	})
	owner := backupstore.New(db.DB())
	if err := owner.RecordRecoveryRuntime(t.Context(), contractrecovery.Runtime{ManagementTLS: "disabled", WorkingDirectory: directory}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().ExecContext(t.Context(), "INSERT INTO metadata(key,value)VALUES('business_value','before')"); err != nil {
		t.Fatal(err)
	}
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := backupstore.NormalizeRecoveryPolicy(contractrecovery.Policy{Recipient: key.Recipient().String(), AllowMaintenance: true, IncludeHistory: true})
	if err != nil {
		t.Fatal(err)
	}
	job := backupstore.RecoveryJob{ID: uuid.New().String(), CreatedAt: time.Now().UTC(), State: "queued", Target: "local", Policy: policy, UpdatePoint: true, IncludesHistory: true}
	if err := owner.EnqueueRecovery(t.Context(), job); err != nil {
		t.Fatal(err)
	}
	executableDir := t.TempDir()
	active, staged := filepath.Join(executableDir, "yuhaiin"), filepath.Join(executableDir, "yuhaiin-update-fixture")
	copyExecutable(t, source, active)
	copyExecutable(t, target, staged)
	old, err := compatibility.Describe(t.Context(), active, "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	next, err := compatibility.Describe(t.Context(), staged, "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	r := Record{ID: uuid.New().String(), Source: old, Target: next, TargetPath: active, StagedPath: staged, BackupJobID: job.ID}
	if err := Begin(t.Context(), directory, r); err != nil {
		t.Fatal(err)
	}
	loaded, err := Read(directory)
	if err != nil {
		t.Fatal(err)
	}
	return directory, *loaded, host, key
}

func TestProtectedUpdatePreservesEncryptedPointAndRequiresActualReadiness(t *testing.T) {
	source, target := binaries(t)
	for _, fault := range []string{"none", "preserve", "startup", "no_receipt", "listener", "prune"} {
		t.Run(fault, func(t *testing.T) {
			directory, r, host, key := deployment(t, source, target)
			host.fault = fault
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			host.cancel = cancel
			err := Run(ctx, directory, r.ID, host)
			current, readErr := Read(directory)
			if readErr != nil {
				t.Fatal(readErr)
			}
			switch fault {
			case "none", "prune":
				if err != nil || current.Phase != "completed" || host.starts != 1 {
					t.Fatal("healthy startup not committed", err, current.Phase, host.starts)
				}
			case "preserve":
				if err == nil || current.Phase != "failed" || host.starts != 1 {
					t.Fatal("pre-install failure did not preserve source", err, current.Phase)
				}
				if err := verify(t.Context(), r.TargetPath, r.Source); err != nil {
					t.Fatal(err)
				}
			default:
				if err == nil || current.Phase != "manual_recovery" || host.starts != 1 {
					t.Fatal("ambiguous target startup was rolled back automatically", err, current.Phase, host.starts)
				}
				if err := verify(t.Context(), r.TargetPath, r.Target); err != nil {
					t.Fatal("target changed after data may have migrated", err)
				}
				if _, err := PrepareStartup(t.Context(), directory, r.TargetPath, "", ""); err == nil {
					t.Fatal("unconfirmed manual recovery restarted target")
				}
			}
			if current.BackupID == "" {
				t.Fatal("no paired recovery point was retained")
			}
			archive, err := os.Open(filepath.Join(directory, ".recovery-archives", r.BackupJobID+".yhb"))
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := backuparchive.Prepare(t.Context(), archive, t.TempDir(), backuparchive.Decryption{Identity: key.String()})
			_ = archive.Close()
			if err != nil {
				t.Fatal("paired archive does not authenticate", err)
			}
			defer prepared.Close()
			if !prepared.Manifest.CompleteInventory || prepared.Manifest.ID != current.BackupID {
				t.Fatal("wrong paired deployment archive")
			}
			raw, err := os.ReadFile(filepath.Join(directory, journalName))
			if err != nil || strings.Contains(string(raw), key.String()) {
				t.Fatal("update journal leaked the private backup identity", err)
			}
			if fault == "startup" {
				if err := prepared.Close(); err != nil {
					t.Fatal(err)
				}
				input, err := os.Open(filepath.Join(directory, ".recovery-archives", r.BackupJobID+".yhb"))
				if err != nil {
					t.Fatal(err)
				}
				defer input.Close()
				preview, err := recovery.Preview(t.Context(), directory, input, backuparchive.Decryption{Identity: key.String()}, "original")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := input.Seek(0, io.SeekStart); err != nil {
					t.Fatal(err)
				}
				restored, err := recovery.Restore(t.Context(), directory, input, backuparchive.Decryption{Identity: key.String()}, recovery.RestoreOptions{Mode: "original", ConfirmedMaintenance: true, ConfirmBackupID: preview.Manifest.ID, ConfirmSourceInstanceID: preview.Manifest.InstanceID, ConfirmTargetInstanceID: preview.TargetInstanceID, ConfirmSourceStopped: true, ConfirmCredentialRevival: true})
				if err != nil {
					t.Fatal("failed-update archive cannot restore the deployment", err)
				}
				if err := os.Remove(r.TargetPath); err != nil {
					t.Fatal(err)
				}
				copyExecutable(t, source, r.TargetPath)
				lease, err := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
				if err != nil {
					t.Fatal(err)
				}
				defer lease.Close()
				startup, err := recovery.PrepareStartup(directory, lease, restored.Runtime)
				if err != nil || startup == nil {
					t.Fatal("restore startup not admitted", err)
				}
				if _, err := PrepareStartup(t.Context(), directory, r.TargetPath, startup.BackupID(), uuid.New().String()); err == nil {
					t.Fatal("clone identity was accepted as original update recovery")
				}
				update, err := PrepareStartup(t.Context(), directory, r.TargetPath, startup.BackupID(), startup.InstanceID())
				if err != nil || update == nil {
					t.Fatal("paired source startup not admitted", err)
				}
				db, err := sqlite.Open(t.Context(), filepath.Join(directory, "state.db"))
				if err != nil {
					t.Fatal(err)
				}
				var value string
				err = db.DB().QueryRowContext(t.Context(), "SELECT value FROM metadata WHERE key='business_value'").Scan(&value)
				if closeErr := db.Close(); err != nil || closeErr != nil || value != "before" {
					t.Fatal("original data did not recover", value, err, closeErr)
				}
				if err := startup.Complete(); err != nil {
					t.Fatal(err)
				}
				if err := update.Complete(t.Context(), "127.0.0.1:1", nil); err != nil {
					t.Fatal(err)
				}
				outcome, err := Read(directory)
				if err != nil || outcome.Phase != "recovered" {
					t.Fatal("actual paired recovery not recorded", err)
				}
			}
		})
	}
}
