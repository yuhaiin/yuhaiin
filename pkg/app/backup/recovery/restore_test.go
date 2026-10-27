package recovery

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
	testfixture "github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/testfixture"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	nodecontract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	managementauth "github.com/Asutorufa/yuhaiin/pkg/management/auth"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tailscale"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	backuparchive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

func recoveryRestoreArchive(t *testing.T) ([]byte, contractrecovery.Manifest, *age.X25519Identity) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("offline activation needs directory synchronization")
	}
	source, key := testfixture.Deployment(t)
	path := filepath.Join(t.TempDir(), "full.yhb")
	manifest, err := Create(t.Context(), source, path, backuparchive.Encryption{Recipient: key.Recipient().String()}, CreateOptions{ConfirmedMaintenance: true})
	if err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return archive, manifest, key
}

func TestRecoveryCloneRotatesMachineKeys(t *testing.T) {
	original := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	document := map[string]any{"type": "wireguard", "wireguard": map[string]any{"secretKey": original}}
	if err := rebindRecoveryDocument(document, func(string) (string, error) { return "", errors.New("no file dependency") }, "clone"); err != nil {
		t.Fatal(err)
	}
	encoded := document["wireguard"].(map[string]any)["secretKey"].(string)
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) != 32 || encoded == original || key[0]&7 != 0 || key[31]&128 != 0 || key[31]&64 == 0 {
		t.Fatal("clone reused or malformed the local machine key")
	}
}

func TestRecoveryRestoredTokenScopeAndRevocationRemainEffective(t *testing.T) {
	source, key := testfixture.Deployment(t)
	identity, err := sqlite.OpenManagement(t.Context(), filepath.Join(source, "management.db"))
	if err != nil {
		t.Fatal(err)
	}
	accounts := managementauth.NewStore(identity.DB())
	actor := managementauth.Principal{UserID: "owner", CredentialType: "session", Permissions: managementauth.RolePermissions(managementauth.Admin)}
	token, err := accounts.IssueToken(t.Context(), actor, "owner", []managementauth.Permission{managementauth.SettingsRead}, 0)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := accounts.IssueToken(t.Context(), actor, "owner", []managementauth.Permission{managementauth.SettingsRead}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.DB().ExecContext(t.Context(), "UPDATE management_credentials SET revoked=1 WHERE id=?", revoked.ID); err != nil {
		t.Fatal(err)
	}
	if err := identity.Close(); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "credentials.yhb")
	manifest, err := Create(t.Context(), source, archivePath, backuparchive.Encryption{Recipient: key.Recipient().String()}, CreateOptions{ConfirmedMaintenance: true})
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	target := t.TempDir()
	_, err = Restore(t.Context(), target, input, backuparchive.Decryption{Identity: key.String()}, RestoreOptions{Mode: "original", ConfirmedMaintenance: true,
		ConfirmBackupID: manifest.ID, ConfirmSourceInstanceID: manifest.InstanceID, ConfirmTargetInstanceID: "empty", ConfirmSourceStopped: true, ConfirmCredentialRevival: true})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := sqlite.OpenSnapshotReader(t.Context(), filepath.Join(target, "management.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	restored := managementauth.NewStore(reader)
	principal, err := restored.Authenticate(t.Context(), token.Secret, "token")
	if err != nil || !principal.Allows(managementauth.SettingsRead) || principal.Allows(managementauth.SettingsWrite) {
		t.Fatal("restored token did not retain its effective scope", err)
	}
	if _, err := restored.Authenticate(t.Context(), revoked.Secret, "token"); !errors.Is(err, managementauth.ErrUnauthorized) {
		t.Fatal("a credential revoked before the snapshot became valid")
	}
}

func TestOfflineRecoveryPreviewRestoreAndRollbackExistingInstance(t *testing.T) {
	archive, manifest, key := recoveryRestoreArchive(t)
	target, _ := testfixture.Deployment(t)
	before, err := os.ReadFile(filepath.Join(target, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	preview, err := Preview(t.Context(), target, bytes.NewReader(archive), backuparchive.Decryption{Identity: key.String()}, "original")
	if err != nil {
		t.Fatal(err)
	}
	if preview.TargetInstanceID == manifest.InstanceID || preview.TargetInstanceID == "unreadable" || preview.Runtime.WorkingDirectory != target {
		t.Fatal("wrong target/original identity or unresolved startup inputs", preview)
	}
	after, err := os.ReadFile(filepath.Join(target, "state.db"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("preview changed live configuration")
	}
	options := RestoreOptions{Mode: "original", ConfirmedMaintenance: true, ConfirmBackupID: manifest.ID, ConfirmSourceInstanceID: manifest.InstanceID, ConfirmTargetInstanceID: preview.TargetInstanceID, ConfirmSourceStopped: true, ConfirmCredentialRevival: true}
	bad := options
	bad.ConfirmCredentialRevival = false
	if _, err := Restore(t.Context(), target, bytes.NewReader(archive), backuparchive.Decryption{Identity: key.String()}, bad); err == nil {
		t.Fatal("older credential validity was restored without confirmation")
	}
	result, err := Restore(t.Context(), target, bytes.NewReader(archive), backuparchive.Decryption{Identity: key.String()}, options)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != "awaiting_startup" || result.InstanceID != manifest.InstanceID {
		t.Fatal("file activation was incorrectly reported as a healthy running service", result)
	}
	identity, err := sqlite.RecoveryInstanceID(t.Context(), filepath.Join(target, "state.db"), false)
	if err != nil || identity != manifest.InstanceID {
		t.Fatal("original instance identity not restored")
	}
	db, err := sqlite.OpenSnapshotReader(t.Context(), filepath.Join(target, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	stored, err := store.NewNodeStore(db).Get(t.Context(), "tls")
	if err != nil || stored.Chain[0].TLSTermination.TLS.Certificates[0].CertFilePath != filepath.Join(target, "site.crt") {
		t.Fatal("relative file dependency was not rebound to restored deployment", stored, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := tailscale.RecoveryFiles(target, nodecontract.Tailscale{AuthKey: "tskey-fixture", Hostname: "fixture-host"})
	if err != nil || len(files) != 1 || !strings.Contains(files[0], "v2-") {
		t.Fatal("legacy Tailnet identity did not reach the current owner's namespace", files, err)
	}
	if err := Rollback(target, result.TransactionID, true); err != nil {
		t.Fatal(err)
	}
	after, err = os.ReadFile(filepath.Join(target, "state.db"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("offline rollback did not restore the exact old database")
	}
	directory, err := tailscale.RecoveryDirectory(target, nodecontract.Tailscale{AuthKey: "tskey-fixture", Hostname: "fixture-host"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rollback left a new namespace that would bypass legacy identity migration")
	}
}

func TestOfflineRecoveryCloneResetsIdentityCredentialsAndListeners(t *testing.T) {
	archive, manifest, key := recoveryRestoreArchive(t)
	target := t.TempDir()
	result, err := Restore(t.Context(), target, bytes.NewReader(archive), backuparchive.Decryption{Identity: key.String()}, RestoreOptions{Mode: "clone", ConfirmedMaintenance: true,
		ConfirmBackupID: manifest.ID, ConfirmSourceInstanceID: manifest.InstanceID, ConfirmTargetInstanceID: "empty"})
	if err != nil {
		t.Fatal(err)
	}
	if result.InstanceID == manifest.InstanceID || result.State != "awaiting_startup" {
		t.Fatal("clone reused the source deployment identity")
	}
	identity, err := sqlite.OpenSnapshotReader(t.Context(), filepath.Join(target, "management.db"))
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := identity.QueryRowContext(t.Context(), "SELECT count(*) FROM management_users").Scan(&count); err != nil || count != 0 {
		t.Fatal("cloned accounts retained source credential verifiers")
	}
	if err := identity.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sqlite.OpenSnapshotReader(t.Context(), filepath.Join(target, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM gateway_ca").Scan(&count); err != nil || count != 0 {
		t.Fatal("clone retained source MITM CA")
	}
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM nodes_v2 WHERE enabled!=0 OR json_extract(data_json,'$.enabled')=1").Scan(&count); err != nil || count != 0 {
		t.Fatal("clone activated source VPN nodes")
	}
	backups, err := backupstore.New(db).Get(t.Context())
	if err != nil || backups.S3.Enabled || backups.Interval != 0 || backups.S3.AccessKey != "" || backups.S3.SecretKey != "" || backups.InstanceName != result.InstanceID {
		t.Fatal("clone can overwrite the source instance's scheduled S3 backups", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"management-tls.pem", "zerotier/fixture/1-0000000000000000-0000000000000000.state"} {
		if _, err := os.Stat(filepath.Join(target, path)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("cloned native/listener identity was installed", path)
		}
	}
	lock, err := lockfile.Acquire(filepath.Join(target, ".configuration.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	startup, err := PrepareStartup(target, lock, result.Runtime)
	if err != nil || startup == nil {
		t.Fatal(err)
	}
	if err := startup.Abort(); err != nil {
		t.Fatal(err)
	}
}
