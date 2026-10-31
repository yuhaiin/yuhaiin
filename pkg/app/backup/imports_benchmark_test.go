package backup

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"path/filepath"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
)

// Measures the actual opaque upload/registry/fsync/discard path. The random
// source buffer is a benchmark fixture, excluded from B/op and elapsed time.
// HTTPS, archive authentication and peak process RSS are not measured here.
func BenchmarkRecoveryImportStaging(b *testing.B) {
	for _, size := range []int{1 << 20, 16 << 20, 64 << 20} {
		b.Run(fmt.Sprintf("%dMiB", size>>20), func(b *testing.B) {
			directory := b.TempDir()
			db, err := sqlite.Open(b.Context(), filepath.Join(directory, "state.db"))
			if err != nil {
				b.Fatal(err)
			}
			defer db.Close()
			owner := &Backup{store: backupstore.New(db.DB()), dir: directory}
			data := make([]byte, size)
			if _, err := rand.Read(data); err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				item, err := owner.UploadRecoveryImport(b.Context(), io.NopCloser(bytes.NewReader(data)), int64(size))
				if err != nil {
					b.Fatal(err)
				}
				if err := owner.DiscardRecoveryImport(b.Context(), item.ID); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
