package update

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/update/compatibility"
)

func TestStagedCompatibilityGuardsRealExecutableAndLiveDatabaseChanges(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("installed-helper executable fixture uses Linux amd64")
	}
	directory := t.TempDir()
	db, err := sqlite.Open(t.Context(), filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Describing this test program never executes a prospective binary. A later
	// tampered regular file must fail before a service manager can stop anything.
	m, err := compatibility.Describe(t.Context(), self, "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(t.TempDir(), "candidate")
	input, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.Create(stage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(output, input); err != nil {
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writeStagedCompatibility(stage, m); err != nil {
		t.Fatal(err)
	}
	if _, status, err := InspectStagedCompatibility(t.Context(), stage, directory); err != nil || status.State != "compatible" {
		t.Fatal("valid same-schema target rejected", status, err)
	}
	if _, err := db.DB().ExecContext(t.Context(), "UPDATE metadata SET value='999' WHERE key='schema_version'"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := InspectStagedCompatibility(t.Context(), stage, directory); !errors.Is(err, sqlite.ErrIncompatibleSchema) {
		t.Fatal("helper ignored a live WAL schema change", err)
	}
	if _, err := db.DB().ExecContext(t.Context(), "UPDATE metadata SET value=(SELECT CAST(MAX(version) AS TEXT) FROM migrate) WHERE key='schema_version'"); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(stage, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("not-a-valid-executable"), 0); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if _, _, err := InspectStagedCompatibility(t.Context(), stage, directory); err == nil {
		t.Fatal("tampered executable accepted")
	}
}

func TestHistoryStoresOwnCapabilitiesAndRefusesInventedLegacyMetadata(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("Linux amd64 helper fixture")
	}
	directory := t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveHistory(directory, self, "fixture", "commit"); err != nil {
		t.Fatal(err)
	}
	entries, err := ListHistory(directory)
	if err != nil || len(entries) != 1 {
		t.Fatal(entries, err)
	}
	descriptor, err := historyCompatibility(directory, entries[0].ID)
	if err != nil || descriptor.SHA256 != entries[0].ID {
		t.Fatal("own capabilities not retained", err)
	}
	staged, err := StageHistory(directory, entries[0].ID, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readCompatibilityFile(staged + compatibility.Suffix); err != nil {
		t.Fatal("history staging lost descriptor", err)
	}
	binary, _ := historyPaths(HistoryDirectory(directory), entries[0].ID)
	if err := os.Remove(binary + compatibility.Suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := historyCompatibility(directory, entries[0].ID); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invented legacy schema metadata", err)
	}
}

func TestReleaseChecksumRejectsAmbiguityAndNormalizesHex(t *testing.T) {
	hash := strings.Repeat("A", 64)
	if got, err := parseChecksum(hash+"  target\n", "target"); err != nil || got != strings.ToLower(hash) {
		t.Fatal(got, err)
	}
	if _, err := parseChecksum(hash+"  a/target\n"+hash+"  b/target\n", "target"); err == nil {
		t.Fatal("duplicate asset digests accepted")
	}
}
