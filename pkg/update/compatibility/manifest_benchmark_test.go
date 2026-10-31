package compatibility

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

// Management preflight, not forwarding performance: includes opening two live
// read-only WAL handles and checking transaction-consistent migration metadata.
func BenchmarkObservedSchemaCompatibility(b *testing.B) {
	directory := b.TempDir()
	state, err := sqlite.Open(b.Context(), filepath.Join(directory, "state.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer state.Close()
	identity, err := sqlite.OpenManagement(b.Context(), filepath.Join(directory, "management.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer identity.Close()
	path := filepath.Join(b.TempDir(), "yuhaiin-linux-amd64")
	if err := os.WriteFile(path, []byte("opaque executable fixture"), 0600); err != nil {
		b.Fatal(err)
	}
	manifest, err := Describe(b.Context(), path, "linux", "amd64")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		status, err := manifest.Check(b.Context(), directory)
		if err != nil || status.State != "compatible" {
			b.Fatal(status, err)
		}
	}
}
