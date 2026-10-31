package statistics

import (
	"path/filepath"
	"testing"
)

func BenchmarkSQLiteTotalCache(b *testing.B) {
	cc := NewSQLiteTotalCache(filepath.Join(b.TempDir(), "state.db"))
	defer cc.Close()

	for i := 0; b.Loop(); i++ {
		cc.AddDownload(uint64(i))
	}
}
