package archive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
	"uuid"

	"filippo.io/age"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func recoveryFixture(t *testing.T) (string, contract.RecoveryManifest, *age.X25519Identity) {
	t.Helper()
	directory := t.TempDir()
	if err := os.MkdirAll(filepath.Join(directory, "identity"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"identity/device.json": []byte("private-device-key")} {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sqlite.Open(t.Context(), filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().ExecContext(t.Context(), "INSERT INTO metadata(key,value) VALUES('archive_fixture',?)", strings.Repeat("private configuration and key material", 7000)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	manifest := contract.RecoveryManifest{
		ID: uuid.New().String(), InstanceID: uuid.New().String(), CreatedAt: time.Now().UTC(), Consistency: "offline-maintenance",
		Build: contract.RecoveryBuild{Version: "fixture", Platform: runtime.GOOS, Architecture: runtime.GOARCH, GoVersion: runtime.Version()},
		Files: []contract.RecoveryFile{{Path: "state.db", Role: "configuration_database", SchemaVersion: 22}, {Path: "identity/device.json", Role: "protocol_identity"}},
	}
	return directory, manifest, identity
}

func encryptedRecoveryFixture(t *testing.T) ([]byte, contract.RecoveryManifest, *age.X25519Identity) {
	t.Helper()
	directory, manifest, key := recoveryFixture(t)
	var encrypted bytes.Buffer
	written, err := Write(t.Context(), &encrypted, directory, manifest, Encryption{Recipient: key.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	return encrypted.Bytes(), written, key
}

func TestRecoveryArchiveStillVerifiesVersionOne(t *testing.T) {
	directory, manifest, key := recoveryFixture(t)
	var current bytes.Buffer
	manifest, err := Write(t.Context(), &current, directory, manifest, Encryption{Recipient: key.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	manifest.Version = 1
	var payload bytes.Buffer
	for _, file := range manifest.Files {
		data, err := os.ReadFile(filepath.Join(directory, file.Path))
		if err != nil {
			t.Fatal(err)
		}
		payload.Write(data)
	}
	archive := maliciousRecovery(t, manifest, payload.Bytes(), key)
	prepared, err := Prepare(t.Context(), bytes.NewReader(archive), t.TempDir(), Decryption{Identity: key.String()})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	if prepared.Manifest.Version != 1 || prepared.Manifest.CompleteInventory {
		t.Fatal("legacy component inventory was incorrectly promoted to a complete deployment")
	}
}

func TestRecoveryManifestStartupAndExternalDependencyBoundaries(t *testing.T) {
	_, valid, _ := encryptedRecoveryFixture(t)
	valid.CompleteInventory = true
	valid.SourceDirectory = "/original/deployment"
	valid.Runtime = &contract.RecoveryRuntime{ManagementTLS: "disabled", WorkingDirectory: "/original/cwd"}
	valid.Files[1].Role = "dependency"
	valid.Files[1].SourcePath = "/external/key.pem"
	if err := ValidateManifest(valid); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*contract.RecoveryManifest){
		func(m *contract.RecoveryManifest) { m.Version = 1 },
		func(m *contract.RecoveryManifest) { m.SourceDirectory = "relative" },
		func(m *contract.RecoveryManifest) { m.Runtime = nil },
		func(m *contract.RecoveryManifest) { m.Runtime.WorkingDirectory = "relative" },
		func(m *contract.RecoveryManifest) { m.Runtime.ManagementAuth = true },
		func(m *contract.RecoveryManifest) { m.Runtime.ManagementTLS = "files" },
		func(m *contract.RecoveryManifest) { m.Runtime.CertificateFile = "/unexpected.pem" },
		func(m *contract.RecoveryManifest) { m.Files[1].SourcePath = "../external/key" },
		func(m *contract.RecoveryManifest) { m.Files[1].Role = "protocol_identity" },
	} {
		bad := valid
		bad.Runtime = new(*valid.Runtime)
		bad.Files = slices.Clone(valid.Files)
		mutate(&bad)
		if err := ValidateManifest(bad); err == nil {
			t.Fatal("incomplete or unsafe startup inventory accepted")
		}
	}
}

func TestRecoveryArchiveEncryptedRoundTripAndPrivateStaging(t *testing.T) {
	directory, manifest, key := recoveryFixture(t)
	var output bytes.Buffer
	written, err := Write(t.Context(), &output, directory, manifest, Encryption{Recipient: key.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(output.Bytes(), []byte("private-device-key")) || bytes.Contains(output.Bytes(), []byte(manifest.InstanceID)) {
		t.Fatal("plaintext escaped encrypted archive")
	}
	// The caller's inventory is not mutated when digests are populated.
	if manifest.Files[0].SHA256 != "" {
		t.Fatal("caller manifest mutated")
	}
	parent := t.TempDir()
	prepared, err := Prepare(t.Context(), bytes.NewReader(output.Bytes()), parent, Decryption{Identity: key.String()})
	if err != nil {
		t.Fatal(err)
	}
	stage := prepared.Directory()
	for _, file := range written.Files {
		want, err := os.ReadFile(filepath.Join(directory, file.Path))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(stage, file.Path))
		if err != nil || !bytes.Equal(want, got) {
			t.Fatal("restored content mismatch")
		}
		info, err := os.Stat(filepath.Join(stage, file.Path))
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Fatal("staged private file permissions")
		}
	}
	if prepared.Manifest.InstanceID != manifest.InstanceID || prepared.Manifest.Files[0].SHA256 != written.Files[0].SHA256 {
		t.Fatal("authenticated manifest changed")
	}
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stage); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("staging directory leaked")
	}
}

func TestRecoveryArchiveRejectsCorruptionWrongIdentityAndTruncation(t *testing.T) {
	original, _, key := encryptedRecoveryFixture(t)
	wrong, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string][]byte{"wrong-identity": bytes.Clone(original), "header": bytes.Clone(original), "middle": bytes.Clone(original), "last-tag": bytes.Clone(original), "truncated-final-byte": original[:len(original)-1], "truncated-chunk": original[:len(original)-65536], "trailing-ciphertext": append(bytes.Clone(original), 1)}
	mutations["header"][5] ^= 1
	mutations["middle"][len(original)/2] ^= 1
	mutations["last-tag"][len(original)-1] ^= 1
	for name, data := range mutations {
		t.Run(name, func(t *testing.T) {
			identity := key
			if name == "wrong-identity" {
				identity = wrong
			}
			parent := t.TempDir()
			prepared, err := Prepare(t.Context(), bytes.NewReader(data), parent, Decryption{Identity: identity.String()})
			if prepared != nil || !errors.Is(err, ErrInvalid) {
				t.Fatalf("bad archive accepted: %v", err)
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatal("failed verification left private staging behind")
			}
		})
	}
}

func maliciousRecovery(t *testing.T, manifest contract.RecoveryManifest, payload []byte, key *age.X25519Identity) []byte {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	encrypted, err := age.Encrypt(&output, key.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(encrypted, recoveryMagic); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(encrypted, binary.BigEndian, uint32(len(data))); err != nil {
		t.Fatal(err)
	}
	if _, err := encrypted.Write(data); err != nil {
		t.Fatal(err)
	}
	if _, err := encrypted.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := encrypted.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestRecoveryManifestAndUntrustedInventory(t *testing.T) {
	_, valid, key := encryptedRecoveryFixture(t)
	for _, name := range []string{"../outside", "/absolute", "C:/private", "nested/../../outside", "nested\\outside", "nested//name", ".", "a/./b", ".configuration.lock", ".recovery-stage-evil/key", "COM1.key", "name:stream", "name.", "name\nkey"} {
		t.Run(name, func(t *testing.T) {
			bad := valid
			bad.Files = append([]contract.RecoveryFile(nil), valid.Files...)
			bad.Files[0].Path = name
			data := maliciousRecovery(t, bad, nil, key)
			parent := t.TempDir()
			if prepared, err := Prepare(t.Context(), bytes.NewReader(data), parent, Decryption{Identity: key.String()}); err == nil {
				_ = prepared.Close()
				t.Fatal("unsafe archive path accepted")
			}
			entries, _ := os.ReadDir(parent)
			if len(entries) != 0 {
				t.Fatal("unsafe inventory created staging files")
			}
		})
	}
	for _, mutate := range []func(*contract.RecoveryManifest){
		func(m *contract.RecoveryManifest) { m.Version++ },
		func(m *contract.RecoveryManifest) { m.Files = nil },
		func(m *contract.RecoveryManifest) { m.Files[0].Size = math.MaxInt64 },
		func(m *contract.RecoveryManifest) { m.Files[0].Size = -1 },
		func(m *contract.RecoveryManifest) { m.Files[0].SHA256 = "bad" },
		func(m *contract.RecoveryManifest) { m.Files[0].Role = "symlink" },
		func(m *contract.RecoveryManifest) { m.Consistency = "independent-live-snapshots" },
		func(m *contract.RecoveryManifest) { m.Files[1].Path = strings.ToUpper(m.Files[0].Path) },
		func(m *contract.RecoveryManifest) {
			m.Files = append(m.Files, contract.RecoveryFile{Path: "state.db/a", Role: "dependency", SHA256: m.Files[0].SHA256}, contract.RecoveryFile{Path: "state.db.b", Role: "dependency", SHA256: m.Files[0].SHA256})
		},
	} {
		bad := valid
		bad.Files = append([]contract.RecoveryFile(nil), valid.Files...)
		mutate(&bad)
		if err := ValidateManifest(bad); err == nil {
			t.Fatal("malicious manifest accepted")
		}
	}
}

func TestRecoveryArchiveRejectsAuthenticatedMissingExtraAndWrongContent(t *testing.T) {
	_, manifest, key := encryptedRecoveryFixture(t)
	manifest.Files = manifest.Files[:1]
	manifest.Files[0].Size = 4
	hash := sha256.Sum256([]byte("data"))
	manifest.Files[0].SHA256 = hex.EncodeToString(hash[:])
	for name, payload := range map[string][]byte{"missing": []byte("dat"), "extra": []byte("dataX"), "hash": []byte("evil")} {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			data := maliciousRecovery(t, manifest, payload, key)
			if prepared, err := Prepare(t.Context(), bytes.NewReader(data), parent, Decryption{Identity: key.String()}); err == nil {
				_ = prepared.Close()
				t.Fatal("invalid authenticated content accepted")
			}
			entries, _ := os.ReadDir(parent)
			if len(entries) != 0 {
				t.Fatal("failed content verification leaked staging")
			}
		})
	}
}

func TestRecoveryArchivePassphraseAndKDFBounds(t *testing.T) {
	directory, manifest, _ := recoveryFixture(t)
	var output bytes.Buffer
	secret := "correct horse recovery fixture"
	if _, err := Write(t.Context(), &output, directory, manifest, Encryption{Passphrase: secret}); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(t.Context(), bytes.NewReader(output.Bytes()), t.TempDir(), Decryption{Passphrase: "incorrect passphrase"}); !errors.Is(err, ErrInvalid) {
		t.Fatal("incorrect passphrase accepted")
	}
	prepared, err := Prepare(t.Context(), bytes.NewReader(output.Bytes()), t.TempDir(), Decryption{Passphrase: secret})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	// Reject malicious scrypt work factors before running an expensive KDF.
	hostile := bytes.Replace(output.Bytes(), []byte(" 18\n"), []byte(" 30\n"), 1)
	if bytes.Equal(hostile, output.Bytes()) {
		t.Fatal("scrypt fixture did not contain default work factor")
	}
	if _, err := Prepare(t.Context(), bytes.NewReader(hostile), t.TempDir(), Decryption{Passphrase: secret}); !errors.Is(err, ErrInvalid) {
		t.Fatal("hostile KDF cost accepted")
	}
}

type recoveryWriteHook struct {
	writer io.Writer
	hook   func()
}

func (w *recoveryWriteHook) Write(p []byte) (int, error) {
	if w.hook != nil {
		hook := w.hook
		w.hook = nil
		hook()
	}
	return w.writer.Write(p)
}

func TestRecoveryCreationRejectsSourceChangesAndCancellation(t *testing.T) {
	directory, manifest, key := recoveryFixture(t)
	var output bytes.Buffer
	writer := &recoveryWriteHook{writer: &output, hook: func() {
		if err := os.WriteFile(filepath.Join(directory, "identity/device.json"), []byte("changed-device-key"), 0o600); err != nil {
			t.Fatal(err)
		}
	}}
	if _, err := Write(t.Context(), writer, directory, manifest, Encryption{Recipient: key.Recipient().String()}); err == nil {
		t.Fatal("source changed after digest but creation succeeded")
	}
	ctx, cancel := context.WithCancel(t.Context())
	writer = &recoveryWriteHook{writer: io.Discard, hook: cancel}
	if _, err := Write(ctx, writer, directory, manifest, Encryption{Recipient: key.Recipient().String()}); !errors.Is(err, context.Canceled) {
		t.Fatalf("creation cancellation lost: %v", err)
	}
	if _, err := Prepare(ctx, bytes.NewReader(output.Bytes()), t.TempDir(), Decryption{Identity: key.String()}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled restore accepted")
	}
}

func TestRecoveryArchiveFilePublicationAndSymlinkProtection(t *testing.T) {
	directory, manifest, key := recoveryFixture(t)
	output := filepath.Join(t.TempDir(), "backup.yhb")
	if _, err := WriteFile(t.Context(), output, directory, manifest, Encryption{Recipient: key.Recipient().String()}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WriteFile(t.Context(), output, directory, manifest, Encryption{Recipient: key.Recipient().String()}); err == nil {
		t.Fatal("existing archive overwritten")
	}
	after, _ := os.ReadFile(output)
	if !bytes.Equal(before, after) {
		t.Fatal("existing archive changed")
	}
	entries, _ := os.ReadDir(filepath.Dir(output))
	if len(entries) != 1 {
		t.Fatal("temporary archive leaked")
	}
	if runtime.GOOS == "windows" {
		return
	}
	if err := os.Remove(filepath.Join(directory, "identity/device.json")); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("outside secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, "identity/device.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Write(t.Context(), io.Discard, directory, manifest, Encryption{Recipient: key.Recipient().String()}); err == nil {
		t.Fatal("symlink included in archive")
	}
}

type appendDuringRecovery struct {
	io.Writer
	append func()
}

func (w *appendDuringRecovery) Write(p []byte) (int, error) {
	if len(p) > 4096 && w.append != nil {
		appendSource := w.append
		w.append = nil
		appendSource()
	}
	return w.Writer.Write(p)
}
func TestRecoveryCreationRejectsSourceGrowthWhileStreaming(t *testing.T) {
	directory, manifest, key := recoveryFixture(t)
	writer := &appendDuringRecovery{Writer: io.Discard, append: func() {
		file, err := os.OpenFile(filepath.Join(directory, "state.db"), os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte("changed while streaming")); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}}
	if _, err := Write(t.Context(), writer, directory, manifest, Encryption{Recipient: key.Recipient().String()}); err == nil {
		t.Fatal("source growth during bounded copy was ignored")
	}
	if writer.append != nil {
		t.Fatal("fixture did not grow the active source")
	}
}
