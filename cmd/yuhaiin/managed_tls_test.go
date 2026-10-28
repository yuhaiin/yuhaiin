package main

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"uuid"

	"filippo.io/age"
	"github.com/Asutorufa/yuhaiin/cmd/yuhaiin/internal/startuphealth"
	recovery "github.com/Asutorufa/yuhaiin/pkg/app/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/cert"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
	managementtls "github.com/Asutorufa/yuhaiin/pkg/management/tls"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	archive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
	"github.com/Asutorufa/yuhaiin/pkg/store/certificates"
)

func TestManagedManagementTLSActualStartupAndRestore(t *testing.T) {
	const actionEnv = "YUH_MANAGED_TLS_ACTION"
	const directoryEnv = "YUH_MANAGED_TLS_DIRECTORY"
	const idEnv = "YUH_MANAGED_TLS_ID"
	const proofEnv = "YUH_MANAGED_TLS_PROOF"
	if action := os.Getenv(actionEnv); action != "" {
		directory, id := os.Getenv(directoryEnv), os.Getenv(idEnv)
		wait = func(ctx context.Context, listeners ...net.Listener) error {
			var pair tls.Certificate
			if action == "clone" {
				value, _, _, err := managementtls.LoadOrCreate(directory, nil)
				if err != nil {
					return err
				}
				pair = value
			} else {
				data, err := os.ReadFile(os.Getenv(proofEnv))
				if err != nil {
					return err
				}
				block, _ := pem.Decode(data)
				if block == nil {
					return errors.New("missing public proof")
				}
				pair.Certificate = [][]byte{block.Bytes}
			}
			return startuphealth.CheckListener(ctx, listeners[0].Addr(), &pair)
		}
		args := []string{"-path", directory, "-host", "127.0.0.1:0", "-https-certificate-id", id}
		if action == "restore" || action == "clone" {
			args = []string{"-path", directory, "-host", "127.0.0.1:1", "-https=false"}
		}
		err := run(args)
		if action == "missing" {
			if err == nil || !strings.Contains(err.Error(), "already issued") {
				t.Fatal("missing certificate did not fail closed", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		return
	}
	if runtime.GOOS == "windows" {
		t.Skip("restore activation requires directory synchronization")
	}
	t.Setenv("EXTERNAL_WEB", "")
	source := recoveryServiceDeployment(t, "managed-tls", "")
	ca, err := cert.GenerateCa()
	if err != nil {
		t.Fatal(err)
	}
	roots, err := ca.CertBytes()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.GenerateServerCert("management.example")
	if err != nil {
		t.Fatal(err)
	}
	chain, err := leaf.CertBytes()
	if err != nil {
		t.Fatal(err)
	}
	private, err := leaf.PrivateKeyBytes()
	if err != nil {
		t.Fatal(err)
	}
	proof := filepath.Join(t.TempDir(), "public-leaf.pem")
	if err := os.WriteFile(proof, chain, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sqlite.Open(t.Context(), filepath.Join(source, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	store := certificates.New(db.DB())
	cfg := contract.Config{ID: uuid.New().String(), Name: "Management", Domains: []string{"management.example"}, DirectoryURL: contract.LetsEncryptStaging, Email: "ops@example.com", TermsAccepted: true, TrustPEM: string(roots), Challenge: contract.Challenge{Type: "http-01", HTTPGatewayID: uuid.New().String()}}
	resource, err := store.Save(t.Context(), cfg, 0)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	owner := uuid.New().String()
	if ok, err := store.Acquire(t.Context(), cfg.ID, resource.Revision, owner, now, time.Minute); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if err := store.Complete(t.Context(), cfg.ID, resource.Revision, owner, now, contract.Status{State: "ready"}, &certificates.Material{CertificatePEM: chain, PrivateKey: certificates.NewSecret(private)}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	invoke := func(t *testing.T, action, directory string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestManagedManagementTLSActualStartupAndRestore$", "-test.v")
		cmd.Env = append(os.Environ(), actionEnv+"="+action, directoryEnv+"="+directory, idEnv+"="+cfg.ID, proofEnv+"="+proof)
		if logs, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("managed TLS %s: %v\n%s", action, err, logs)
		}
	}
	invoke(t, "start", source)
	invoke(t, "restart", source)
	db, err = sqlite.Open(t.Context(), filepath.Join(source, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := backupstore.LoadRecoveryRuntime(t.Context(), db.DB())
	if err != nil || inputs == nil || inputs.ManagementTLS != "managed" || inputs.ManagedCertificateID != cfg.ID {
		t.Fatal("runtime does not record actual managed identity", inputs, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "managed.yhb")
	manifest, err := recovery.Create(t.Context(), source, path, archive.Encryption{Recipient: key.Recipient().String()}, recovery.CreateOptions{ConfirmedMaintenance: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"original", "clone"} {
		t.Run(mode, func(t *testing.T) {
			target := t.TempDir()
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			result, err := recovery.Restore(t.Context(), target, file, archive.Decryption{Identity: key.String()}, recovery.RestoreOptions{Mode: mode, ConfirmedMaintenance: true, ConfirmBackupID: manifest.ID, ConfirmSourceInstanceID: manifest.InstanceID, ConfirmTargetInstanceID: "empty", ConfirmSourceStopped: true, ConfirmCredentialRevival: true, AdoptStartup: true})
			if err != nil {
				t.Fatal(err)
			}
			action := "restore"
			if mode == "clone" {
				action = "clone"
				if result.Runtime.ManagementTLS != "self_signed" || result.Runtime.ManagedCertificateID != "" {
					t.Fatal("clone reused source identity", result.Runtime)
				}
			}
			invoke(t, action, target)
		})
	}
	db, err = sqlite.Open(t.Context(), filepath.Join(source, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().ExecContext(t.Context(), "DELETE FROM managed_certificate_material"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	invoke(t, "missing", source)
}

func TestManagedManagementTLSRejectsAmbiguousFlags(t *testing.T) {
	for _, args := range [][]string{
		{"-https=false"}, {"-https-cert", "site.pem", "-https-key", "site.key"}, {"-https-names", "site.example"},
	} {
		args = append(args, "-https-certificate-id", uuid.New().String(), "-path", t.TempDir())
		if err := run(args); err == nil || !strings.Contains(err.Error(), "excludes") {
			t.Fatal("ambiguous TLS source accepted", args, err)
		}
	}
}
