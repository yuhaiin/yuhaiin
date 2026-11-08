package interfaces

import "testing"

// One network monitor refresh: interfaces, addresses, routes and lifecycle.
func BenchmarkNetworkRefresh(b *testing.B) {
	if err := reGetDefaultInterface("benchmark"); err != nil {
		b.Skip(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if err := reGetDefaultInterface("benchmark"); err != nil {
			b.Fatal(err)
		}
	}
}
