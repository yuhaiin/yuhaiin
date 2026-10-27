package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/Asutorufa/yuhaiin/pkg/app"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
)

func TestRecoveryManagedStartupServiceDrill(t *testing.T) {
	const actionVariable = "YUH_MANAGED_RECOVERY_ACTION"
	const directoryVariable = "YUH_MANAGED_RECOVERY_DIRECTORY"
	if action := os.Getenv(actionVariable); action != "" {
		directory := os.Getenv(directoryVariable)
		wait = func(ctx context.Context, listeners ...net.Listener) error {
			result, err := app.LastRecoveryResult(directory)
			if err != nil || result == nil || !result.AdoptStartup || result.Runtime.ManagementTLS != "files" {
				return errors.New("service did not commit its managed file certificate")
			}
			workingDirectory, err := os.Getwd()
			if err != nil || workingDirectory != result.Runtime.WorkingDirectory || os.Getenv("EXTERNAL_WEB") != result.Runtime.ExternalWebDirectory {
				return errors.New("service retained stale working directory or web assets")
			}
			if _, err := os.Stat(filepath.Join(result.Runtime.ExternalWebDirectory, "index.html")); err != nil {
				return err
			}
			certificate, err := tls.LoadX509KeyPair(result.Runtime.CertificateFile, result.Runtime.KeyFile)
			if err != nil {
				return err
			}
			return checkRecoveryListener(ctx, listeners[0].Addr(), &certificate)
		}
		if action == "crash" {
			recoveryStartupCheckpoint = func(string) { os.Exit(42) }
		}
		// These host inputs are deliberately incompatible with the archived TLS,
		// port, working directory and external assets. Adoption must precede all
		// identity/configuration/TLS owners; a fallback would fail this drill.
		err := run([]string{"-path", directory, "-https=false", "-host", "127.0.0.1:1", "-eweb", "/missing-managed-recovery-assets"})
		switch action {
		case "invalid-certificate":
			if err == nil || !strings.Contains(err.Error(), "PEM") {
				t.Fatal("invalid restored certificate was accepted or bypassed", err)
			}
		case "failed-inbound":
			if err == nil || !strings.Contains(err.Error(), "inbound failed") {
				t.Fatal("occupied restored listener was accepted", err)
			}
		case "recover-interruption":
			if err == nil || !strings.Contains(err.Error(), "rolled back") {
				t.Fatal("interrupted managed startup was accepted", err)
			}
		default:
			if err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	if runtime.GOOS == "windows" {
		t.Skip("durable activation requires directory synchronization")
	}
	t.Setenv("EXTERNAL_WEB", "")
	target := recoveryServiceDeployment(t, "original", "")
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	archiveDirectory := t.TempDir()
	identityPath := filepath.Join(archiveDirectory, "private-key")
	if err := os.WriteFile(identityPath, []byte(identity.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	prepareRestore := func(t *testing.T, source, name string) contract.RecoveryRestoreResult {
		t.Helper()
		archive := filepath.Join(archiveDirectory, name+".yhb")
		var output bytes.Buffer
		if err := executeRecoveryCommand(t.Context(), []string{"create", "-path", source, "-archive", archive, "-maintenance", "-recipient", identity.Recipient().String()}, &output); err != nil {
			t.Fatal(err)
		}
		output.Reset()
		if err := executeRecoveryCommand(t.Context(), []string{"preview", "-path", target, "-archive", archive, "-identity-file", identityPath, "-mode", "original"}, &output); err != nil {
			t.Fatal(err)
		}
		var preview contract.RecoveryRestorePreview
		if err := json.Unmarshal(output.Bytes(), &preview); err != nil {
			t.Fatal(err)
		}
		output.Reset()
		arguments := []string{"restore", "-path", target, "-archive", archive, "-identity-file", identityPath, "-mode", "original", "-maintenance", "-source-stopped", "-restore-credentials", "-adopt-startup", "-confirm-backup", preview.Manifest.ID, "-confirm-source-instance", preview.Manifest.InstanceID, "-confirm-target-instance", preview.TargetInstanceID}
		if err := executeRecoveryCommand(t.Context(), arguments, &output); err != nil {
			t.Fatal(err)
		}
		var result contract.RecoveryRestoreResult
		if err := json.Unmarshal(output.Bytes(), &result); err != nil || !result.AdoptStartup {
			t.Fatal("restore did not opt in to startup adoption", err)
		}
		return result
	}
	invoke := func(t *testing.T, action string) ([]byte, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRecoveryManagedStartupServiceDrill$", "-test.v")
		command.Env = append(os.Environ(), actionVariable+"="+action, directoryVariable+"="+target)
		return command.CombinedOutput()
	}
	requireStart := func(t *testing.T, action string) {
		t.Helper()
		if logs, err := invoke(t, action); err != nil {
			t.Fatalf("actual managed startup failed: %v\n%s", err, logs)
		}
	}
	source := recoveryServiceDeployment(t, "file-certificate", "")
	certificate, err := os.ReadFile(filepath.Join(source, "management-tls.pem"))
	if err != nil {
		t.Fatal(err)
	}
	site := filepath.Join(source, "site.pem")
	if err := os.WriteFile(site, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	web := filepath.Join(source, "web-assets")
	if err := os.Mkdir(web, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(web, "index.html"), []byte("managed-recovery-assets"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sqlite.Open(t.Context(), filepath.Join(source, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.NewBackupStore(db.DB()).RecordRecoveryRuntime(t.Context(), contract.RecoveryRuntime{ManagementAuth: true, ManagementTLS: "files", CertificateFile: site, KeyFile: site, WorkingDirectory: source, ListenAddress: "127.0.0.1:0", ExternalWebDirectory: web}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	first := prepareRestore(t, source, "first")
	for range 3 {
		requireStart(t, "healthy") // Pending, committed journal, then result-only.
	}

	for _, fault := range []string{"failed-inbound", "invalid-certificate", "crash"} {
		t.Run(fault, func(t *testing.T) {
			occupied, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer occupied.Close()
			address := ""
			if fault == "failed-inbound" {
				address = occupied.Addr().String()
			}
			broken := recoveryServiceDeployment(t, "failed-deployment", address)
			brokenDB, err := sqlite.Open(t.Context(), filepath.Join(broken, "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			inputs := contract.RecoveryRuntime{ManagementAuth: true, ManagementTLS: "self_signed", WorkingDirectory: broken, ListenAddress: "127.0.0.1:0"}
			if fault == "invalid-certificate" {
				invalid := filepath.Join(broken, "invalid-site.pem")
				if err := os.WriteFile(invalid, []byte("invalid certificate fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
				inputs.ManagementTLS, inputs.CertificateFile, inputs.KeyFile = "files", invalid, invalid
			}
			if err := store.NewBackupStore(brokenDB.DB()).RecordRecoveryRuntime(t.Context(), inputs); err != nil {
				t.Fatal(err)
			}
			if err := brokenDB.Close(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(filepath.Join(target, "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			prepareRestore(t, broken, fault)
			if fault == "crash" {
				logs, err := invoke(t, "crash")
				if exited, ok := errors.AsType[*exec.ExitError](err); !ok || exited.ExitCode() != 42 {
					t.Fatalf("real managed startup crash not reached: %v\n%s", err, logs)
				}
				requireStart(t, "recover-interruption")
			} else {
				requireStart(t, fault)
			}
			after, err := os.ReadFile(filepath.Join(target, "state.db"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("managed rollback changed the original database", err)
			}
			result, err := app.LastRecoveryResult(target)
			if err != nil || result == nil || result.State != "rolled_back" || result.Runtime != first.Runtime || result.InstanceID != first.InstanceID || !result.AdoptStartup {
				t.Fatal("managed rollback lost its preceding binding", err)
			}
			requireStart(t, "healthy")
		})
	}
}
