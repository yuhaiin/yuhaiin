package update

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	contractupdate "github.com/Asutorufa/yuhaiin/pkg/contract/update"
)

func TestHistoryRetainsTwoPreviousBinaries(t *testing.T) {
	dataDir := t.TempDir()
	executable := filepath.Join(t.TempDir(), "yuhaiin")
	write := func(value string) {
		t.Helper()
		if err := os.WriteFile(executable, []byte(value), 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []string{"version-one", "version-two", "version-three"} {
		write(value)
		if err := SaveHistory(dataDir, executable, value, "test-commit"); err != nil {
			t.Fatal(err)
		}
	}
	write("version-four")
	// The old snapshots survive until the new executable is confirmed running.
	before, err := ListHistory(dataDir)
	if err != nil || len(before) != 3 {
		t.Fatalf("before=%v err=%v", before, err)
	}
	if err := PruneHistory(dataDir, executable); err != nil {
		t.Fatal(err)
	}
	after, err := ListHistory(dataDir)
	if err != nil || len(after) != 2 {
		t.Fatalf("after=%v err=%v", after, err)
	}
	versions := make(map[string]bool)
	for _, entry := range after {
		versions[entry.Version] = true
	}
	if !versions["version-three"] || !versions["version-two"] || versions["version-one"] {
		t.Fatalf("retained incorrect versions: %#v", versions)
	}
}

func TestStageHistoryRejectsTampering(t *testing.T) {
	dataDir, stageDir := t.TempDir(), t.TempDir()
	executable := filepath.Join(t.TempDir(), "yuhaiin")
	if err := os.WriteFile(executable, []byte("original"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := SaveHistory(dataDir, executable, "v1.0.0", "abc"); err != nil {
		t.Fatal(err)
	}
	history, err := ListHistory(dataDir)
	if err != nil || len(history) != 1 {
		t.Fatalf("history=%v err=%v", history, err)
	}
	stage, err := StageHistory(dataDir, history[0].ID, stageDir)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(stage)
	if err != nil || string(data) != "original" {
		t.Fatalf("stage=%q err=%v", data, err)
	}
	_ = os.Remove(stage)

	binary, _ := historyPaths(HistoryDirectory(dataDir), history[0].ID)
	if err := os.WriteFile(binary, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := StageHistory(dataDir, history[0].ID, stageDir); err == nil {
		t.Fatal("expected history checksum mismatch")
	}
	if _, err := StageHistory(dataDir, "../etc/passwd", stageDir); err == nil {
		t.Fatal("expected invalid history ID rejection")
	}
}

func TestHistoryRejectsUntrustedFilesystemEntries(t *testing.T) {
	dataDir := t.TempDir()
	dir := HistoryDirectory(dataDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, strings.Repeat("a", 64)+".json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	results, err := ListHistory(dataDir)
	if err != nil || len(results) != 0 {
		t.Fatalf("results=%v err=%v", results, err)
	}
	if validHistoryID(strings.Repeat("A", 64)) {
		t.Fatal("uppercase ID must be rejected")
	}
}

func TestHistoryResultUsesTypedEntries(t *testing.T) {
	item := contractupdate.HistoryEntry{ID: strings.Repeat("a", 64)}
	if !validHistoryID(item.ID) {
		t.Fatal("valid SHA256 rejected")
	}
}
