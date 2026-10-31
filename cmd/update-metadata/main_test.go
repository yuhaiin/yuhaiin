package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/update/compatibility"
)

func TestMetadataGenerationInspectsInsteadOfExecutingCandidate(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("host metadata fixture uses Linux amd64")
	}
	directory := t.TempDir()
	marker := filepath.Join(directory, "must-not-run")
	source := filepath.Join(directory, "main.go")
	if err := os.WriteFile(source, []byte("package main\nimport \"os\"\nfunc main(){os.WriteFile("+strconv.Quote(marker)+",[]byte(\"ran\"),0600)}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(directory, "yuhaiin-linux-amd64")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, source)
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "GOAMD64=v1", "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fixture: %v: %s", err, output)
	}
	if err := run(binary, "linux", "amd64"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(binary + compatibility.Suffix)
	if err != nil {
		t.Fatal(err)
	}
	m, err := compatibility.Parse(data)
	if err != nil || m.Size == 0 || m.Asset != "yuhaiin-linux-amd64" {
		t.Fatal("invalid generated descriptor", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("metadata generator executed candidate", err)
	}
	if err := run(binary, "darwin", "amd64"); err == nil {
		t.Fatal("mislabelled platform accepted")
	}
	if err := run(binary, "linux", "amd64v3"); err == nil {
		t.Fatal("mislabelled CPU level accepted")
	}
	// The builder runs on a baseline host even when the prospective executable
	// requires AVX-512. Parsing it must not execute those instructions.
	advanced := filepath.Join(directory, "yuhaiin-linux-amd64v4")
	build = exec.CommandContext(t.Context(), "go", "build", "-ldflags=-s -w", "-o", advanced, source)
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "GOAMD64=v4", "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build prospective CPU fixture: %v: %s", err, output)
	}
	if err := run(advanced, "linux", "amd64v4"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("advanced-CPU candidate was executed", err)
	}
}
