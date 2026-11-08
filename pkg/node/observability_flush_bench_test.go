package node

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

// BenchmarkNodeObserverFlush measures one periodic flush with 200 nodes that
// carry probes and health histories, of which "active" nodes moved traffic.
func BenchmarkNodeObserverFlush(b *testing.B) {
	for _, active := range []int{0, 10} {
		b.Run(fmt.Sprintf("nodes=200/active=%d", active), func(b *testing.B) {
			store, err := storagesqlite.Open(b.Context(), filepath.Join(b.TempDir(), "state.db"))
			if err != nil {
				b.Fatal(err)
			}
			defer store.Close()
			o, err := newNodeObserver(b.Context(), store.DB())
			if err != nil {
				b.Fatal(err)
			}
			defer o.close()
			now := time.Now().UnixMilli()
			counters := make([]*nodeCounters, 200)
			for i := range counters {
				v := sampleNodeTotals()
				v.TCPHealth.Samples = make([]contract.HealthSample, 32)
				for j := range v.TCPHealth.Samples {
					v.TCPHealth.Samples[j] = contract.HealthSample{Sequence: uint64(j + 1), At: now, OK: true, RTTMS: 10, Kind: "tcp", Target: "example.com:443"}
				}
				v.TCPHealth.Sequence = 32
				counters[i] = o.counter(fmt.Sprint("node-", i))
				counters[i].restore(v)
			}
			if err := o.flush(b.Context()); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				for _, c := range counters[:active] {
					c.download.Add(16384)
				}
				if err := o.flush(b.Context()); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
