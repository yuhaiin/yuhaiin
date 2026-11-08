package statistics

import (
	"fmt"
	"testing"
)

// BenchmarkUserUsageAuditFlush persists one audit checkpoint per live session.
func BenchmarkUserUsageAuditFlush(b *testing.B) {
	r := usageTestRecorder(b)
	for i := range 500 {
		r.register(usageInfo(fmt.Sprint(i%50), fmt.Sprint(i%64), fmt.Sprint(i%4)), new(usageTestCounter), nil)
	}
	b.ReportAllocs()
	for b.Loop() {
		r.mu.Lock()
		for s := range r.sessions {
			r.auditLocked(s.audit)
		}
		r.mu.Unlock()
		if err := r.Flush(b.Context()); err != nil {
			b.Fatal(err)
		}
	}
}
