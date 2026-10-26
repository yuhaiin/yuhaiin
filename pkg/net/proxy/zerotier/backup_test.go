package zerotier

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

func TestRecoveryFilesOnlyIncludesOwnedStateObjects(t *testing.T) {
	base := t.TempDir()
	input := contract.ZeroTier{NetworkID: "8056c2e21c000001", Identity: "fixture"}
	if files, err := RecoveryFiles(base, input); err != nil || len(files) != 0 {
		t.Fatal("uninitialized identity must remain uninitialized")
	}
	if entries, err := os.ReadDir(base); err != nil || len(entries) != 0 {
		t.Fatal("inventory initialized native storage")
	}
	directory := filepath.Join(base, "zerotier", "fixture")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	name := "1-0000000000000000-0000000000000000.state"
	for _, name := range []string{name, ".zt-state-temporary", "debug.log", "other.state"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files, err := RecoveryFiles(base, input)
	if err != nil || !slices.Equal(files, []string{filepath.Join(directory, name)}) {
		t.Fatalf("unexpected state inventory: %v %v", files, err)
	}
	input.Identity = "../outside"
	if _, err := RecoveryFiles(base, input); err == nil {
		t.Fatal("invalid identity namespace accepted")
	}
	input.Identity = ""
	if files, err := RecoveryFiles(base, input); err != nil || len(files) != 0 {
		t.Fatal("network-default namespace selected another identity")
	}
	if err := os.Remove(filepath.Join(directory, name)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(directory, name), 0o700); err != nil {
		t.Fatal(err)
	}
	input.Identity = "fixture"
	if _, err := RecoveryFiles(base, input); err == nil {
		t.Fatal("state object directory accepted as regular identity")
	}
}

func TestRecoveryNetworkNamespaceDoesNotRequireNativeBridge(t *testing.T) {
	base := t.TempDir()
	directory := filepath.Join(base, "zerotier", "8056c2e21c000001")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "1-0000000000000000-0000000000000000.state")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := RecoveryFiles(base, contract.ZeroTier{NetworkID: "8056C2E21C000001"})
	if err != nil || !slices.Equal(files, []string{path}) {
		t.Fatal("default namespace differs from the native core's canonical network ID", files, err)
	}
	for _, id := range []string{"", "0000000000000000", "8056c2e21c0000011", "not-a-network-id"} {
		if _, err := RecoveryFiles(base, contract.ZeroTier{NetworkID: id}); err == nil {
			t.Fatal("invalid network identifier accepted")
		}
	}
}
