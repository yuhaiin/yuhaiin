package maintenance

import (
	"os"
	"path/filepath"
	"testing"
)

// Measures durable coordinator work and the existing encrypted snapshot owner.
// Service readiness is synchronous in this fixture; this is not a downtime test.
func BenchmarkProtectedUpdateCoordinator(b *testing.B) {
	source, target := binaries(b)
	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		directory, record, host, _ := deployment(b, source, target)
		b.StartTimer()
		err := Run(b.Context(), directory, record.ID, host)
		b.StopTimer()
		if err != nil {
			b.Fatal(err)
		}
		if err := os.RemoveAll(directory); err != nil {
			b.Fatal(err)
		}
		if err := os.RemoveAll(filepath.Dir(record.TargetPath)); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
}
