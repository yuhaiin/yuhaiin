package backup

import (
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
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

func TestLocalPointRetentionIsOptInBoundedAndCopied(t *testing.T) {
	legacy, err := NormalizeRecoveryPolicy(contractrecovery.Policy{})
	if err != nil || legacy.LocalPoints != nil {
		t.Fatal("legacy point deletion enabled", legacy, err)
	}
	original := &contractrecovery.PointRetention{Enabled: true}
	normalized, err := NormalizeRecoveryPolicy(contractrecovery.Policy{LocalPoints: original})
	if err != nil || normalized.LocalPoints.KeepCount != 3 || normalized.LocalPoints.KeepDays != 30 || original.KeepCount != 0 {
		t.Fatal("local policy was not normalized independently", normalized, err)
	}
	for _, p := range []contractrecovery.PointRetention{{KeepCount: -1}, {KeepCount: 1001}, {KeepDays: -1}, {KeepDays: 3651}} {
		if _, err := NormalizePointRetention(p); err == nil {
			t.Fatal("invalid point retention accepted", p)
		}
	}
}
