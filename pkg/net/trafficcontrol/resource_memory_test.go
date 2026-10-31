package trafficcontrol

import (
	"context"
	"fmt"
	"runtime"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol/quota"
)

// Initial, unused windows have no durable records. This isolates snapshot heap
// ownership from SQLite caches, socket buffers and network throughput.
type initialQuotaStore struct{}

func (initialQuotaStore) Load(_ context.Context, key quota.Key) (quota.Record, error) {
	return quota.Record{Key: key}, nil
}
func (initialQuotaStore) Save(context.Context, []quota.Record) error { return nil }

func (initialQuotaStore) Reclaim(context.Context, []quota.Reclaim) error { return nil }

func BenchmarkResourceSnapshotMemory(b *testing.B) {
	for _, devices := range []int{1, 4, 64} {
		b.Run(fmt.Sprintf("devices=%d", devices), func(b *testing.B) {
			quotas := []resource.Quota{{ID: "day", Period: "daily", Combined: "9223372036854775807", Action: "warn"}, {ID: "month", Period: "monthly", Combined: "9223372036854775807", Action: "warn"}, {ID: "life", Period: "lifetime", Combined: "9223372036854775807", Action: "warn"}}
			config := resource.Config{Enabled: true, DefaultUser: resource.Policy{Quotas: quotas}}
			var groupIDs []string
			for i := range 64 {
				id := fmt.Sprintf("group-%02d", i)
				groupIDs = append(groupIDs, id)
				config.Groups = append(config.Groups, resource.GroupPolicy{GroupID: id, SharedProfile: Profile{Upload: Rate{BytesPerSecond: 1 << 40}}, Quotas: quotas})
			}
			bindings := make([]IdentityBinding, 0, 1024*devices)
			for user := range 1024 {
				for device := range devices {
					bindings = append(bindings, IdentityBinding{UserID: fmt.Sprint(user), CredentialID: fmt.Sprintf("%d/%d", user, device), GroupIDs: groupIDs})
				}
			}
			for b.Loop() {
				runtime.GC()
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				ledger := quota.New(initialQuotaStore{})
				manager := NewManagerWithQuotas(ledger)
				if err := manager.ApplyResources(config, bindings); err != nil {
					b.Fatal(err)
				}
				runtime.GC()
				runtime.ReadMemStats(&after)
				heap := after.HeapAlloc - before.HeapAlloc
				b.ReportMetric(float64(heap), "retained-B")
				b.ReportMetric(float64(heap)/1024, "retained-B/user")
				b.ReportMetric(float64(heap)/float64(len(bindings)), "retained-B/credential")
				runtime.KeepAlive(manager)
				if err := ledger.Close(context.Background()); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
