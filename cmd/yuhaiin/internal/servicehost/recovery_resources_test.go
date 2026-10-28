//go:build linux

package servicehost

import (
	"crypto/sha256"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/Asutorufa/yuhaiin/pkg/app/backup/recovery"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
)

// Called only by the explicitly enabled isolated systemd drill. Measures the
// public offline workflow through real startup, without production fault hooks.
func measureOfflineRecovery(t *testing.T, sizeMiB int, directory, web string, identity *age.X25519Identity, service func(...string) error, ready func() bool) {
	t.Helper()
	asset := filepath.Join(web, "resource-fixture.bin")
	file, err := os.OpenFile(asset, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	assetBytes := int64(sizeMiB) << 20
	_, firstErr := file.WriteAt([]byte("resource-fixture-start"), 0)
	_, lastErr := file.WriteAt([]byte("resource-fixture-end"), assetBytes-20)
	closeErr := file.Close()
	if firstErr != nil || lastErr != nil || closeErr != nil {
		t.Fatal("cannot seed the bounded resource fixture", firstErr, lastErr, closeErr)
	}
	hashFile := func() [32]byte {
		t.Helper()
		input, err := os.Open(asset)
		if err != nil {
			t.Fatal(err)
		}
		defer input.Close()
		sum := sha256.New()
		size, err := io.Copy(sum, input)
		if err != nil || size != assetBytes {
			t.Fatal("resource fixture byte count differs", size, err)
		}
		return [32]byte(sum.Sum(nil))
	}
	expected := hashFile()
	private := t.TempDir()
	keyPath, archive := filepath.Join(private, "recovery.key"), filepath.Join(private, "resource.yhb")
	if err := os.WriteFile(keyPath, []byte(identity.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	type measurement struct {
		Operation           string `json:"operation"`
		AssetBytes          int64  `json:"assetBytes"`
		CiphertextBytes     int64  `json:"ciphertextBytes"`
		CommandMS           int64  `json:"commandMs"`
		MaintenanceWindowMS int64  `json:"maintenanceWindowMs"`
		CommandMaxRSSKiB    int64  `json:"commandMaxRssKiB"`
	}
	invoke := func(action string, output any, flags ...string) measurement {
		t.Helper()
		args := append([]string{"recovery", action, "-path", directory, "-archive", archive}, flags...)
		// A fresh low-RSS parent measures exactly one backend child. Measuring
		// fork/exec directly from this Go test can inherit its pre-exec RSS peak.
		const wrapper = `import json, resource, subprocess, sys, time
started = time.monotonic()
completed = subprocess.run(sys.argv[1:], capture_output=True, timeout=300, check=True)
elapsed = (time.monotonic() - started) * 1000
print(json.dumps(dict(result=json.loads(completed.stdout), elapsedMs=int(elapsed),
                     rssKiB=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)))`
		command := exec.CommandContext(t.Context(), "/usr/bin/python3", append([]string{"-c", wrapper, "/app/yuhaiin"}, args...)...)
		command.Env = append(os.Environ(), "GOMEMLIMIT=64MiB")
		data, err := command.Output()
		if err != nil {
			if exited, ok := errors.AsType[*exec.ExitError](err); ok {
				t.Logf("resource command diagnostic: %s", strings.ReplaceAll(string(exited.Stderr), identity.String(), "[redacted]"))
			}
			t.Fatal("resource fixture CLI failed", action, err)
		}
		var measured struct {
			Result    jsontext.Value `json:"result"`
			ElapsedMS int64          `json:"elapsedMs"`
			RSSKiB    int64          `json:"rssKiB"`
		}
		if err := json.Unmarshal(data, &measured); err != nil || measured.RSSKiB <= 0 {
			t.Fatal("invalid resource measurement", err)
		}
		result := measurement{Operation: action, AssetBytes: assetBytes, CommandMS: measured.ElapsedMS, CommandMaxRSSKiB: measured.RSSKiB}
		if output != nil {
			if err := json.Unmarshal(measured.Result, output); err != nil {
				t.Fatal("invalid resource fixture CLI output", err)
			}
		}
		return result
	}
	finishMaintenance := func(started time.Time, result measurement, transaction string) {
		t.Helper()
		// This fixture deliberately performs many maintenance restarts within
		// ten seconds. A reviewed manual restart resets systemd's prior burst
		// counter; do not disable the service's real start-rate protection.
		if err := service("reset-failed", "yuhaiin.service"); err != nil {
			t.Fatal(err)
		}
		if err := service("start", "yuhaiin.service"); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(45 * time.Second)
		for {
			complete := ready()
			if complete && transaction != "" {
				status, err := recovery.RestoreStatus(t.Context(), directory)
				complete = err == nil && status.Result != nil && status.Result.State == "committed" && status.Result.TransactionID == transaction
			}
			if complete {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("actual restored management API did not become ready")
			}
			time.Sleep(20 * time.Millisecond)
		}
		result.MaintenanceWindowMS = time.Since(started).Milliseconds()
		info, err := os.Stat(archive)
		if err != nil {
			t.Fatal(err)
		}
		result.CiphertextBytes = info.Size()
		data, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("recovery_resource=%s", data)
	}
	started := time.Now()
	if err := service("stop", "yuhaiin.service"); err != nil {
		t.Fatal(err)
	}
	var manifest contract.Manifest
	created := invoke("create", &manifest, "-recipient", identity.Recipient().String(), "-maintenance")
	finishMaintenance(started, created, "")
	var preview contract.RestorePreview
	invoke("preview", &preview, "-identity-file", keyPath, "-mode", "original")
	// A same-sized change proves that actual content was restored, not just an
	// existing file size or a successful service-manager Start call.
	changed, err := os.OpenFile(asset, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := changed.WriteAt([]byte("changed after backup"), 0)
	if err := changed.Close(); writeErr != nil || err != nil {
		t.Fatal("cannot change the resource fixture", writeErr, err)
	}
	started = time.Now()
	if err := service("stop", "yuhaiin.service"); err != nil {
		t.Fatal(err)
	}
	var activated contract.RestoreResult
	restored := invoke("restore", &activated, "-identity-file", keyPath, "-mode", "original", "-maintenance", "-source-stopped", "-restore-credentials", "-adopt-startup",
		"-confirm-backup", preview.Manifest.ID, "-confirm-source-instance", preview.Manifest.InstanceID, "-confirm-target-instance", preview.TargetInstanceID)
	finishMaintenance(started, restored, activated.TransactionID)
	status, err := recovery.RestoreStatus(t.Context(), directory)
	if err != nil || status.Result == nil || status.Result.State != "committed" || status.Result.BackupID != manifest.ID || hashFile() != expected {
		t.Fatal("real large restore/startup/content verification failed", err)
	}
}
