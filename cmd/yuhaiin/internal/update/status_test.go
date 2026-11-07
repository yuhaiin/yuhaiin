package updatecmd

import (
	"bytes"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/update/compatibility"
	"github.com/Asutorufa/yuhaiin/pkg/update/maintenance"
	"uuid"
)

func TestUpdateStatusReportsRecoveryStepsForFailedPreparation(t *testing.T) {
	directory, binaries := t.TempDir(), t.TempDir()
	describe := func(name string) compatibility.Manifest {
		path := filepath.Join(binaries, name)
		if err := os.WriteFile(path, []byte(name), 0700); err != nil {
			t.Fatal(err)
		}
		m, err := compatibility.Describe(t.Context(), path, runtime.GOOS, runtime.GOARCH)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	r := maintenance.Record{ID: uuid.New().String(), Source: describe("yuhaiin"), Target: describe("yuhaiin-update-x"), TargetPath: filepath.Join(binaries, "yuhaiin"), StagedPath: filepath.Join(binaries, "yuhaiin-update-x"), AllowNoPoint: true}
	if err := maintenance.Begin(t.Context(), directory, r); err != nil {
		t.Fatal(err)
	}
	if err := maintenance.SetPhase(t.Context(), directory, r.ID, "failed", "preparation_failed_source_preserved"); err != nil {
		t.Fatal(err)
	}
	// An adoption record that does not validate must never be reported.
	if err := os.WriteFile(filepath.Join(directory, ".update-adoption.json"), []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := executeUpdateStatus([]string{"-path", directory}, &output); err != nil {
		t.Fatal(err)
	}
	var report struct {
		Phase     string   `json:"phase"`
		ErrorCode string   `json:"errorCode"`
		Adoption  any      `json:"adoption"`
		NextSteps []string `json:"nextSteps"`
	}
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err, output.String())
	}
	if report.Phase != "failed" || report.ErrorCode != "preparation_failed_source_preserved" || report.Adoption != nil {
		t.Fatal("unexpected status", output.String())
	}
	if !strings.Contains(strings.Join(report.NextSteps, "\n"), "update-adopt -path") {
		t.Fatal("status omits the adoption step", report.NextSteps)
	}
}
