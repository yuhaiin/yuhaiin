//go:build linux && !android

package localwrap

import (
	"slices"
	"testing"
)

func TestWrapEnvironmentTimezone(t *testing.T) {
	initial := []string{"PATH=/bin", "TZ=Europe/Berlin", "USER=alice"}
	inherited := wrapEnvironment(initial, "")
	if !slices.Equal(inherited, initial) {
		t.Fatalf("empty timezone must inherit caller environment: %v", inherited)
	}
	overridden := wrapEnvironment(initial, "Asia/Tokyo")
	if !slices.Equal(overridden, []string{"PATH=/bin", "USER=alice", "TZ=Asia/Tokyo"}) {
		t.Fatalf("configured timezone must replace inherited TZ: %v", overridden)
	}
	if initial[1] != "TZ=Europe/Berlin" {
		t.Fatalf("mutated caller environment: %v", initial)
	}
	if got := wrapEnvironment([]string{"PATH=/bin"}, "UTC"); !slices.Contains(got, "TZ=UTC") {
		t.Fatalf("did not add timezone to child environment: %v", got)
	}
}
