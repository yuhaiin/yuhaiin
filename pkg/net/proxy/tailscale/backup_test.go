package tailscale

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

func TestRecoveryFilesUsesConfiguredIdentityWithoutInitializing(t *testing.T) {
	base := t.TempDir()
	input := contract.Tailscale{Hostname: "example", AuthKey: "fixture-key"}
	files, err := RecoveryFiles(base, input)
	if err != nil || len(files) != 0 {
		t.Fatalf("uninitialized identity: %v %v", files, err)
	}
	if entries, err := os.ReadDir(base); err != nil || len(entries) != 0 {
		t.Fatal("inventory initialized protocol storage")
	}
	legacy := filepath.Join(base, "tailscale", input.Hostname)
	current, err := statePath(base, Config{Hostname: input.Hostname, AuthKey: input.AuthKey})
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{legacy, current} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"lite.json", "tailscaled.state", "debug.log"} {
			if err := os.WriteFile(filepath.Join(directory, name), []byte("fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		files, err := RecoveryFiles(base, input)
		want := []string{filepath.Join(directory, "lite.json"), filepath.Join(directory, "tailscaled.state")}
		if err != nil || !slices.Equal(files, want) {
			t.Fatalf("wrong identity inventory: %v %v", files, err)
		}
	}
	// A fresh configuration must not pick up another credential's current state.
	input.AuthKey = "other-key"
	input.Hostname = "different"
	if files, err := RecoveryFiles(base, input); err != nil || len(files) != 0 {
		t.Fatal("unrelated identity selected")
	}
}
