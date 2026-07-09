package app

import (
	"context"
	"testing"

	contractsettings "github.com/Asutorufa/yuhaiin/pkg/contract/settings"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func TestBackupSQLiteSnapshotRestore(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sqliteStore, err := storagesqlite.Open(context.Background(), paths.PathGenerator.State(dir))
	if err != nil {
		t.Fatalf("open sqlite failed: %v", err)
	}
	settings := plainstore.NewSettingsStore(sqliteStore.DB())

	if _, err := settings.Save(context.Background(), contractsettings.Settings{NetInterface: "before"}); err != nil {
		t.Fatalf("write initial sqlite config failed: %v", err)
	}

	backup := &Backup{dir: dir}
	snapshot, err := backup.snapshotStateDB(context.Background())
	if err != nil {
		t.Fatalf("snapshot sqlite state failed: %v", err)
	}

	if _, err := settings.Save(context.Background(), contractsettings.Settings{NetInterface: "after"}); err != nil {
		t.Fatalf("write modified sqlite config failed: %v", err)
	}
	if err := sqliteStore.Close(); err != nil {
		t.Fatalf("close sqlite before restore failed: %v", err)
	}

	if err := backup.restoreStateDB(snapshot); err != nil {
		t.Fatalf("restore sqlite state failed: %v", err)
	}

	reopened, err := storagesqlite.Open(context.Background(), paths.PathGenerator.State(dir))
	if err != nil {
		t.Fatalf("reopen sqlite failed: %v", err)
	}
	defer reopened.Close()
	reopenedSettings := plainstore.NewSettingsStore(reopened.DB())
	got, err := reopenedSettings.Load(context.Background())
	if err != nil {
		t.Fatalf("view restored sqlite config failed: %v", err)
	}
	if got.NetInterface != "before" {
		t.Fatalf("expected restored net interface before, got %q", got.NetInterface)
	}
}
