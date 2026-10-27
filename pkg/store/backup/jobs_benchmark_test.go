package backup

import (
	"path/filepath"
	"strconv"
	"testing"
	"time"
	"uuid"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func BenchmarkRecoveryHistory(b *testing.B) {
	for _, count := range []int{100, 1000} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			db, err := sqlite.Open(b.Context(), filepath.Join(b.TempDir(), "state.db"))
			if err != nil {
				b.Fatal(err)
			}
			defer db.Close()
			owner := New(db.DB())
			for i := range count {
				job := RecoveryJob{ID: uuid.New().String(), CreatedAt: time.Unix(int64(i+1), 0), Target: "local", State: "queued", Size: 1 << 20, Policy: contract.RecoveryPolicy{Target: "local", TimeoutMinutes: 30, KeepCount: 10, KeepDays: 30}}
				if err := owner.EnqueueRecovery(b.Context(), job); err != nil {
					b.Fatal(err)
				}
				job.State = "local_ready"
				if err := owner.SaveRecoveryJob(b.Context(), job, "queued"); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				items, err := owner.RecoveryHistory(b.Context())
				if err != nil || len(items) != count {
					b.Fatal("history query failed", err, len(items))
				}
			}
		})
	}
}
