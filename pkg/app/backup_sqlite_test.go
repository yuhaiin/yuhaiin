package app

import (
	"context"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/chore"
	"github.com/Asutorufa/yuhaiin/pkg/schema/config"
	"github.com/Asutorufa/yuhaiin/pkg/schema/tools"
)

func TestBackupSQLiteSnapshotRestore(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	db := chore.NewSqliteDB(tools.PathGenerator.State(dir))

	if err := db.Batch(func(s *config.Setting) error {
		s.SetNetInterface("before")
		return nil
	}); err != nil {
		t.Fatalf("write initial sqlite config failed: %v", err)
	}

	backup := &Backup{db: db}
	snapshot, err := backup.snapshotStateDB(context.Background())
	if err != nil {
		t.Fatalf("snapshot sqlite state failed: %v", err)
	}

	if err := db.Batch(func(s *config.Setting) error {
		s.SetNetInterface("after")
		return nil
	}); err != nil {
		t.Fatalf("write modified sqlite config failed: %v", err)
	}

	if err := backup.restoreStateDB(snapshot); err != nil {
		t.Fatalf("restore sqlite state failed: %v", err)
	}

	reopened := chore.NewSqliteDB(tools.PathGenerator.State(dir))
	if err := reopened.View(func(s *config.Setting) error {
		if got := s.GetNetInterface(); got != "before" {
			t.Fatalf("expected restored net interface before, got %q", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("view restored sqlite config failed: %v", err)
	}
}
