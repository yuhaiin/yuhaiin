package main

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"uuid"

	"filippo.io/age"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

func TestRecoveryCLIKeyGenerationAndOfflineVerification(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "external-backup.key")
	var stdout bytes.Buffer
	if err := executeRecoveryCommand(t.Context(), []string{"keygen", "-identity-file", keyPath}, &stdout); err != nil {
		t.Fatal(err)
	}
	var generated struct {
		Recipient string `json:"recipient"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &generated); err != nil {
		t.Fatal(err)
	}
	secret, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := age.ParseX25519Identity(strings.TrimSpace(string(secret)))
	if err != nil {
		t.Fatal(err)
	}
	if generated.Recipient != identity.Recipient().String() || bytes.Contains(stdout.Bytes(), secret) || strings.Contains(stdout.String(), "AGE-SECRET-KEY") {
		t.Fatal("key generation exposed private identity")
	}
	if err := executeRecoveryCommand(t.Context(), []string{"keygen", "-identity-file", keyPath}, &stdout); err == nil {
		t.Fatal("existing key file overwritten")
	}
	snapshot := filepath.Join(directory, "snapshot")
	if err := os.Mkdir(snapshot, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sqlite.Open(t.Context(), filepath.Join(snapshot, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().ExecContext(t.Context(), "INSERT INTO metadata(key,value) VALUES('archive_fixture','private snapshot fixture')"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	manifest := contract.RecoveryManifest{ID: uuid.New().String(), InstanceID: uuid.New().String(), CreatedAt: time.Now().UTC(), Consistency: "offline-maintenance", Build: contract.RecoveryBuild{Version: "fixture", Platform: runtime.GOOS, Architecture: runtime.GOARCH, GoVersion: runtime.Version()}, Files: []contract.RecoveryFile{{Path: "state.db", Role: "configuration_database", SchemaVersion: 22}}}
	archive := filepath.Join(directory, "full.yhb")
	if _, err := backupstore.WriteRecoveryArchiveFile(t.Context(), archive, snapshot, manifest, backupstore.RecoveryEncryption{Recipient: generated.Recipient}); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if err := executeRecoveryCommand(t.Context(), []string{"verify", "-archive", archive, "-identity-file", keyPath, "-staging-parent", directory}, &stdout); err != nil {
		t.Fatal(err)
	}
	var verified contract.RecoveryManifest
	if err := json.Unmarshal(stdout.Bytes(), &verified); err != nil {
		t.Fatal(err)
	}
	if verified.InstanceID != manifest.InstanceID || verified.Files[0].SHA256 == "" {
		t.Fatal("CLI did not return verified inventory")
	}
	if strings.Contains(stdout.String(), "private snapshot fixture") || strings.Contains(stdout.String(), "AGE-SECRET-KEY") {
		t.Fatal("CLI verification leaked content")
	}
	entries, err := filepath.Glob(filepath.Join(directory, ".recovery-*"))
	if err != nil || len(entries) != 0 {
		t.Fatal("CLI verification leaked private staging")
	}
	if _, err := os.Stat(filepath.Join(directory, "management.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("verification opened deployment identity database")
	}
}

func TestRecoverySecretFilePermissionsAndNoSecretErrors(t *testing.T) {
	directory := t.TempDir()
	file := filepath.Join(directory, "key")
	const secret = "sensitive-key-fixture"
	if err := os.WriteFile(file, []byte(secret+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readRecoverySecretFile(file); err != nil || got != secret {
		t.Fatal("secret line ending handling failed")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(file, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := readRecoverySecretFile(file); err == nil || strings.Contains(err.Error(), secret) {
			t.Fatal("public secret file accepted or echoed")
		}
		if err := os.Chmod(file, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(file, bytes.Repeat([]byte("x"), 1026), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRecoverySecretFile(file); err == nil {
		t.Fatal("oversize secret file accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := executeRecoveryCommand(ctx, []string{"keygen", "-identity-file", filepath.Join(directory, "cancelled.key")}, &bytes.Buffer{}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled key generation accepted")
	}
}

func TestServerAndLocalAuthRespectRecoveryLifecycleLock(t *testing.T) {
	directory := t.TempDir()
	owner, err := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
	if errors.Is(err, errors.ErrUnsupported) {
		t.Skip("lifecycle lock unsupported")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err := run([]string{"-path", directory, "-host", "127.0.0.1:0", "-https=false"}); err == nil {
		t.Fatal("server ignored offline lifecycle owner")
	}
	if err := authCommand([]string{"recover", "-path", directory, "-id", "fixture"}); err == nil {
		t.Fatal("local auth ignored offline lifecycle owner")
	}
	for _, file := range []string{"management.db", "state.db", "management-tls.pem"} {
		if _, err := os.Stat(filepath.Join(directory, file)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("blocked startup mutated deployment data")
		}
	}
}

func TestRecoveryCLICreatesAndVerifiesCompleteDeploymentWithoutServer(t *testing.T) {
	directory := t.TempDir()
	database, err := sqlite.Open(t.Context(), filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := backupstore.New(database.DB()).RecordRecoveryRuntime(t.Context(), contract.RecoveryRuntime{ManagementTLS: "disabled", WorkingDirectory: directory}); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "full.yhb")
	var output bytes.Buffer
	args := []string{"create", "-path", directory, "-archive", archive, "-recipient", identity.Recipient().String()}
	if err := executeRecoveryCommand(t.Context(), args, &output); err == nil {
		t.Fatal("CLI did not require maintenance acknowledgement")
	}
	args = append(args, "-maintenance")
	if err := executeRecoveryCommand(t.Context(), args, &output); err != nil {
		t.Fatal(err)
	}
	var manifest contract.RecoveryManifest
	if err := json.Unmarshal(output.Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	if !manifest.CompleteInventory || manifest.Runtime == nil || manifest.Runtime.ManagementTLS != "disabled" || manifest.SourceDirectory == "" {
		t.Fatal("CLI did not create complete deployment metadata")
	}
	keyPath := filepath.Join(t.TempDir(), "private.key")
	if err := os.WriteFile(keyPath, []byte(identity.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := executeRecoveryCommand(t.Context(), []string{"verify", "-archive", archive, "-identity-file", keyPath}, &output); err != nil {
		t.Fatal(err)
	}
	var verified contract.RecoveryManifest
	if err := json.Unmarshal(output.Bytes(), &verified); err != nil || verified.ID != manifest.ID {
		t.Fatal("CLI-created deployment archive did not verify")
	}
	if _, err := os.Stat(filepath.Join(directory, "management.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("CLI unexpectedly started management identities")
	}
	if _, err := os.Stat(filepath.Join(directory, "management-tls.pem")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("CLI unexpectedly generated a listener identity")
	}
}
