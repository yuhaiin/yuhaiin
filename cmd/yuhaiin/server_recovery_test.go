package main

import (
	"bytes"
	"context"
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
	recoverycmd "github.com/Asutorufa/yuhaiin/cmd/yuhaiin/internal/recovery"
	"github.com/Asutorufa/yuhaiin/cmd/yuhaiin/internal/startuphealth"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	inboundcontract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	managementtls "github.com/Asutorufa/yuhaiin/pkg/management/tls"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
)

func recoveryServiceDeployment(t *testing.T, marker, inboundAddress string) string {
	t.Helper()
	directory := t.TempDir()
	db, err := sqlite.Open(t.Context(), filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := backupstore.New(db.DB()).RecordRecoveryRuntime(t.Context(), contractrecovery.Runtime{ManagementAuth: true, ManagementTLS: "self_signed", WorkingDirectory: directory}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().ExecContext(t.Context(), "INSERT INTO metadata(key,value) VALUES('recovery_drill',?)", marker); err != nil {
		t.Fatal(err)
	}
	if inboundAddress == "" {
		inboundAddress = "127.0.0.1:0"
	}
	config := inboundcontract.Inbound{ID: "drill", Name: "Drill listener", Enabled: true,
		Network:  inboundcontract.NewTypedNetwork(inboundcontract.TCPUDPNetwork{Host: inboundAddress, UDP: inboundcontract.UDPDisabled}),
		Protocol: inboundcontract.NewTypedProtocol(inboundcontract.MixedProtocol{})}
	if err := store.NewInboundStore(db.DB()).Save(t.Context(), config, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().ExecContext(t.Context(), "INSERT INTO dns_settings(id,server,fakedns_enabled) VALUES(1,'',0)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().ExecContext(t.Context(), "INSERT INTO inbound_settings(id,hijack_dns,hijack_dns_fakeip,sniff_enabled) VALUES(1,0,0,0)"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	identity, err := sqlite.OpenManagement(t.Context(), filepath.Join(directory, "management.db"))
	if err != nil {
		t.Fatal(err)
	}
	// Complete the initialization latch without emitting an enrollment secret.
	// This verifier fixture proves persistence/startup, not a login exchange.
	if _, err := identity.DB().ExecContext(t.Context(), "INSERT INTO management_users(id,login,role,client_salt,credential,created_at,updated_at) VALUES('drill','drill','admin',randomblob(16),randomblob(32),1,1)"); err != nil {
		t.Fatal(err)
	}
	if err := identity.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := managementtls.LoadOrCreate(directory, []string{"localhost"}); err != nil {
		t.Fatal(err)
	}
	return directory
}

// Runs the actual server lifecycle in separate processes because application
// startup owns global network, DNS and metrics state. Only local listeners are
// used. A real exit(42) leaves open SQLite/WAL owners and skips every defer.
func TestRecoveryServiceStartupDrill(t *testing.T) {
	const marker = "YUH_RECOVERY_SERVICE_DRILL"
	const targetVariable = "YUH_RECOVERY_SERVICE_DIRECTORY"
	if action := os.Getenv(marker); action != "" {
		directory := os.Getenv(targetVariable)
		wait = func(ctx context.Context, listeners ...net.Listener) error {
			certificate, _, _, err := managementtls.LoadOrCreate(directory, []string{"localhost"})
			if err != nil {
				return err
			}
			return startuphealth.CheckListener(ctx, listeners[0].Addr(), &certificate)
		}
		if action == "crash" {
			recoveryStartupCheckpoint = func(label string) {
				if label == "after_application" {
					os.Exit(42)
				}
			}
		}
		err := run([]string{"-path", directory, "-host", "127.0.0.1:0"})
		if action == "failed-inbound" {
			if err == nil || !strings.Contains(err.Error(), "inbound failed") {
				t.Fatal("failed restored listener was accepted", err)
			}
			return
		}
		if action == "recover-interruption" {
			if err == nil || !strings.Contains(err.Error(), "rolled back") {
				t.Fatal("crashed startup was accepted", err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	if runtime.GOOS == "windows" {
		t.Skip("offline activation requires directory synchronization")
	}
	t.Setenv("EXTERNAL_WEB", "")
	for _, action := range []string{"healthy", "clone", "failed-inbound", "crash"} {
		t.Run(action, func(t *testing.T) {
			occupied, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer occupied.Close()
			address := ""
			if action == "failed-inbound" {
				address = occupied.Addr().String()
			}
			source := recoveryServiceDeployment(t, "archived", address)
			target := recoveryServiceDeployment(t, "original", "")
			before, err := os.ReadFile(filepath.Join(target, "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			identity, err := age.GenerateX25519Identity()
			if err != nil {
				t.Fatal(err)
			}
			backupDirectory := t.TempDir()
			identityPath := filepath.Join(backupDirectory, "key")
			if err := os.WriteFile(identityPath, []byte(identity.String()), 0o600); err != nil {
				t.Fatal(err)
			}
			archive := filepath.Join(backupDirectory, "full.yhb")
			var output bytes.Buffer
			if err := recoverycmd.Execute(t.Context(), []string{"create", "-path", source, "-archive", archive, "-maintenance", "-recipient", identity.Recipient().String()}, &output); err != nil {
				t.Fatal(err)
			}
			output.Reset()
			if err := recoverycmd.Execute(t.Context(), []string{"preview", "-path", target, "-archive", archive, "-identity-file", identityPath, "-mode", "original"}, &output); err != nil {
				t.Fatal(err)
			}
			var preview contractrecovery.RestorePreview
			if err := json.Unmarshal(output.Bytes(), &preview); err != nil {
				t.Fatal(err)
			}
			output.Reset()
			mode := "original"
			if action == "clone" {
				mode = "clone"
			}
			arguments := []string{"restore", "-path", target, "-archive", archive, "-identity-file", identityPath, "-mode", mode, "-maintenance", "-source-stopped", "-restore-credentials", "-confirm-backup", preview.Manifest.ID, "-confirm-source-instance", preview.Manifest.InstanceID, "-confirm-target-instance", preview.TargetInstanceID}
			if err := recoverycmd.Execute(t.Context(), arguments, &output); err != nil {
				t.Fatal(err)
			}
			invoke := func(action string) ([]byte, error) {
				ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
				defer cancel()
				command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRecoveryServiceStartupDrill$", "-test.v")
				command.Env = append(os.Environ(), marker+"="+action, targetVariable+"="+target)
				return command.CombinedOutput()
			}
			logs, err := invoke(action)
			if action == "crash" {
				if exited, ok := errors.AsType[*exec.ExitError](err); !ok || exited.ExitCode() != 42 {
					t.Fatalf("real crash was not reached: %v\n%s", err, logs)
				}
				logs, err = invoke("recover-interruption")
			}
			if err != nil {
				t.Fatalf("real service recovery: %v\n%s", err, logs)
			}
			if action == "failed-inbound" && !bytes.Contains(logs, []byte("address already in use")) {
				t.Fatal("occupied-port fault was not reached")
			}
			if action == "healthy" || action == "clone" {
				var status struct {
					Phase string `json:"phase"`
				}
				data, err := os.ReadFile(filepath.Join(target, ".recovery-transaction.json"))
				if err != nil || json.Unmarshal(data, &status) != nil || status.Phase != "committed" {
					t.Fatal("successful real startup was not committed", err)
				}
				db, err := sqlite.OpenSnapshotReader(t.Context(), filepath.Join(target, "state.db"))
				if err != nil {
					t.Fatal(err)
				}
				var value string
				if err := db.QueryRowContext(t.Context(), "SELECT value FROM metadata WHERE key='recovery_drill'").Scan(&value); err != nil || value != "archived" {
					t.Fatal("startup loaded the wrong configuration")
				}
				_ = db.Close()
			} else {
				after, err := os.ReadFile(filepath.Join(target, "state.db"))
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("failed/crashed startup did not restore exact original SQLite state")
				}
				if logs, err := invoke("old-startup"); err != nil {
					t.Fatalf("rolled-back service did not actually restart: %v\n%s", err, logs)
				}
			}
		})
	}
}
