package backup

import (
	"path/filepath"
	"sync"
	"testing"

	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestBackupIdentifierInitializationPreservesConcurrentSettings(t *testing.T) {
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := New(db.DB())
	for range 20 {
		if _, err := db.DB().ExecContext(t.Context(), "DELETE FROM backup_settings"); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				if _, err := store.Get(t.Context()); err != nil {
					t.Error(err)
				}
			})
		}
		if err := store.Save(t.Context(), contractbackup.Option{InstanceName: "administrator", Interval: 137}); err != nil {
			t.Fatal(err)
		}
		wg.Wait()
		got, err := store.Get(t.Context())
		if err != nil || got.InstanceName != "administrator" || got.Interval != 137 {
			t.Fatalf("identifier initialization overwrote settings: %+v, %v", got, err)
		}
	}
}
