package yuhaiin

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
	recovery "github.com/Asutorufa/yuhaiin/pkg/app/backup/recovery"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	backuparchive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
)

func TestPendingRecoveryBlocksAndroidOwnersBeforeDatabaseWrites(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("offline activation requires directory synchronization")
	}
	source, target := t.TempDir(), t.TempDir()
	db, err := sqlite.Open(t.Context(), filepath.Join(source, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := backupstore.New(db.DB()).RecordRecoveryRuntime(t.Context(), contractrecovery.Runtime{ManagementTLS: "disabled", WorkingDirectory: source}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "full.yhb")
	manifest, err := recovery.Create(t.Context(), source, archive, backuparchive.Encryption{Recipient: identity.Recipient().String()}, recovery.CreateOptions{ConfirmedMaintenance: true})
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	_, err = recovery.Restore(t.Context(), target, input, backuparchive.Decryption{Identity: identity.String()}, recovery.RestoreOptions{
		Mode: "original", ConfirmedMaintenance: true, ConfirmBackupID: manifest.ID,
		ConfirmSourceInstanceID: manifest.InstanceID, ConfirmTargetInstanceID: "empty",
		ConfirmSourceStopped: true, ConfirmCredentialRevival: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(target, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	SetSavePath(target)
	preferences := appStore.(*sqlitePreferenceStore)
	err = preferences.withDB(func(_ context.Context, _ *sql.DB) error {
		t.Fatal("pending restore opened the preference database")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "pending recovery") {
		t.Fatal("preference access did not refuse pending restore", err)
	}
	if _, err := ExportConfig(); err == nil {
		t.Fatal("configuration export migrated a pending restore")
	}
	if err := ImportConfig([]byte(`{}`)); err == nil {
		t.Fatal("configuration import wrote to a pending restore")
	}
	var instance App
	if err := instance.Start(nil); err == nil {
		t.Fatal("Android start bypassed pending restore coordination")
	}
	after, err := os.ReadFile(filepath.Join(target, "state.db"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("Android access changed the pending database", err)
	}
	if preferences.store != nil {
		t.Fatal("Android preference owner was created during a pending restore")
	}
}
