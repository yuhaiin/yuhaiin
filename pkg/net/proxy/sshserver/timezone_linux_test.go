//go:build linux && !android

package sshserver

import (
	"slices"
	"strings"
	"testing"
)

func TestSessionEnvironmentTimezone(t *testing.T) {
	config := Config{Shell: "/bin/sh"}
	base := sessionEnvironment(config, "/home/alice", "alice")
	for _, entry := range base {
		if strings.HasPrefix(entry, "TZ=") {
			t.Fatalf("unset timezone must inherit the host: %q", entry)
		}
	}
	if !slices.Contains(base, "HOME=/home/alice") || !slices.Contains(base, "USER=alice") {
		t.Fatalf("session environment lost its identity: %v", base)
	}
	config.Timezone = "Asia/Tokyo"
	overridden := sessionEnvironment(config, "/home/alice", "alice")
	if !slices.Contains(overridden, "TZ=Asia/Tokyo") {
		t.Fatalf("configured child timezone was not set: %v", overridden)
	}
	for _, entry := range base {
		if strings.HasPrefix(entry, "TZ=") {
			t.Fatalf("base environment was mutated: %v", base)
		}
	}
}
