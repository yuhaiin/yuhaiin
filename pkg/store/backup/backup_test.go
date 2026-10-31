package backup

import (
	"errors"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/security/secret"
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

func TestManagedBackupSettingsPreserveAndProtectSecrets(t *testing.T) {
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := New(db.DB())
	original := contractbackup.Option{InstanceName: "instance", Interval: 1, S3: contractbackup.S3{AccessKey: "access", SecretKey: "private", EndpointURL: "https://example.test/private?key=proof"}}
	if err := store.Save(t.Context(), original); err != nil {
		t.Fatal(err)
	}
	masked, err := secret.Redact(original)
	if err != nil {
		t.Fatal(err)
	}
	masked.Interval = 2
	ctx := secret.WithCapabilities(t.Context(), secret.Capabilities{})
	if err := store.Save(ctx, masked); err != nil {
		t.Fatal("metadata save failed", err)
	}
	got, err := store.Get(t.Context())
	if err != nil || got.Interval != 2 || got.S3 != original.S3 {
		t.Fatal("metadata save lost backup secrets", err)
	}
	masked, err = secret.Redact(got)
	if err != nil {
		t.Fatal(err)
	}
	masked.S3.SecretKey = "replacement"
	if err := store.Save(ctx, masked); !errors.Is(err, secret.ErrManage) {
		t.Fatal("secret replacement accepted without authority", err)
	}
	got, err = store.Get(t.Context())
	if err != nil || got.S3 != original.S3 {
		t.Fatal("denied save changed persisted secrets", err)
	}
}
