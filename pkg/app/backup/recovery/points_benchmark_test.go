package recovery

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

// Measures the actual startup plan while retaining all copies: metadata I/O,
// validation, sorting, pinning and policy evaluation; never payload contents.
func BenchmarkPointRetentionPlan(b *testing.B) {
	for _, count := range []int{100, 1000} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			directory := b.TempDir()
			now := time.Now()
			for index := range count {
				makeLocalPoint(b, directory, now.Add(-time.Duration(index+1)*time.Minute), "committed")
			}
			owner, err := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
			if err != nil {
				b.Fatal(err)
			}
			defer owner.Close()
			policy := contract.PointRetention{Enabled: true, KeepCount: 1000, KeepDays: 3650}
			b.ReportAllocs()
			for b.Loop() {
				result, err := PrunePointsWithLifecycle(b.Context(), directory, owner, policy)
				if err != nil || len(result.Deleted) != 0 || result.Retained+result.Protected != count {
					b.Fatal(result, err)
				}
			}
			b.ReportMetric(float64(count), "points/op")
			if _, err := os.Stat(filepath.Join(directory, pointCleanupJournal)); !os.IsNotExist(err) {
				b.Fatal("plan wrote a deletion journal", err)
			}
		})
	}
}
