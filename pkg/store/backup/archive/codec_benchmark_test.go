package archive

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"uuid"

	"filippo.io/age"

	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

// Measures digesting, schema inspection and external-key archive encryption.
// Source fixture creation and disk output are outside this benchmark; it is
// neither peak-RSS measurement nor a complete deployment backup benchmark.
func BenchmarkRecoveryArchiveExternalRecipient(b *testing.B) {
	for _, size := range []int64{1 << 20, 16 << 20, 64 << 20} {
		b.Run(fmt.Sprintf("%dMiB", size>>20), func(b *testing.B) {
			directory := b.TempDir()
			db, err := sqlite.Open(b.Context(), filepath.Join(directory, "state.db"))
			if err != nil {
				b.Fatal(err)
			}
			if err := db.Close(); err != nil {
				b.Fatal(err)
			}
			source, err := os.Create(filepath.Join(directory, "identity.bin"))
			if err != nil {
				b.Fatal(err)
			}
			if err := source.Truncate(size); err != nil {
				b.Fatal(err)
			}
			if err := source.Close(); err != nil {
				b.Fatal(err)
			}
			key, err := age.GenerateX25519Identity()
			if err != nil {
				b.Fatal(err)
			}
			encryption := Encryption{Recipient: key.Recipient().String()}
			schema, err := sqlite.SupportedSchemaVersion("configuration")
			if err != nil {
				b.Fatal(err)
			}
			manifest := contractrecovery.Manifest{
				ID: uuid.New().String(), InstanceID: uuid.New().String(), CreatedAt: time.Now().UTC(), Consistency: "offline-maintenance",
				Build: contractrecovery.Build{Version: "benchmark", Platform: runtime.GOOS, Architecture: runtime.GOARCH, GoVersion: runtime.Version()},
				Files: []contractrecovery.File{{Path: "state.db", Role: "configuration_database", SchemaVersion: schema}, {Path: "identity.bin", Role: "protocol_identity"}},
			}
			b.SetBytes(size)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := Write(b.Context(), io.Discard, directory, manifest, encryption); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
