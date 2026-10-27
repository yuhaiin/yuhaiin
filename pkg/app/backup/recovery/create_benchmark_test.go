package recovery

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	backuparchive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
)

// Includes SQLite snapshot/validation, reference inventory, bounded asset copy,
// hashing and encrypted disk publication. Fixture creation and password KDF are
// excluded. This measures cumulative allocations, not peak process RSS.
func BenchmarkFullRecoveryCreateExternalRecipient(b *testing.B) {
	for _, size := range []int64{1 << 20, 16 << 20, 64 << 20} {
		b.Run(fmt.Sprintf("%dMiB", size>>20), func(b *testing.B) {
			directory := b.TempDir()
			assets := filepath.Join(directory, "web")
			if err := os.Mkdir(assets, 0o700); err != nil {
				b.Fatal(err)
			}
			asset, err := os.Create(filepath.Join(assets, "fixture.bin"))
			if err != nil {
				b.Fatal(err)
			}
			if err := asset.Truncate(size); err != nil {
				b.Fatal(err)
			}
			if err := asset.Close(); err != nil {
				b.Fatal(err)
			}
			db, err := sqlite.Open(b.Context(), filepath.Join(directory, "state.db"))
			if err != nil {
				b.Fatal(err)
			}
			if err := backupstore.New(db.DB()).RecordRecoveryRuntime(b.Context(), contract.RecoveryRuntime{ManagementTLS: "disabled", WorkingDirectory: directory, ExternalWebDirectory: assets}); err != nil {
				b.Fatal(err)
			}
			if err := db.Close(); err != nil {
				b.Fatal(err)
			}
			identity, err := age.GenerateX25519Identity()
			if err != nil {
				b.Fatal(err)
			}
			key := backuparchive.Encryption{Recipient: identity.Recipient().String()}
			destination := filepath.Join(b.TempDir(), "full.yhb")
			b.ReportAllocs()
			b.SetBytes(size)
			for b.Loop() {
				if _, err := Create(b.Context(), directory, destination, key, CreateOptions{ConfirmedMaintenance: true}); err != nil {
					b.Fatal(err)
				}
				if err := os.Remove(destination); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
