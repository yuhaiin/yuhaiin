package recovery

import (
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"uuid"

	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
)

// The maintenance guard must recognize a pending transaction containing
// nested destination directories on every supported filesystem path syntax.
func TestRecoveryMaintenanceGuardValidatesNestedJournalDirectories(t *testing.T) {
	for _, tc := range []struct {
		name, directory string
		valid           bool
	}{
		{"owned nested directory", "identity/devices", true},
		{"unowned sibling directory", "identity/devices-other", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			tx := recoveryTransaction{
				Version: 1, ID: uuid.New().String(), BackupID: uuid.New().String(), InstanceID: uuid.New().String(),
				Phase: "activating", Stage: ".recovery-stage-test", CreatedAt: time.Now().UTC(),
				Runtime:            contractrecovery.Runtime{ManagementTLS: "disabled", WorkingDirectory: directory},
				Moves:              []recoveryMove{{Path: filepath.FromSlash("identity/devices/key.pem"), Install: true}},
				CreatedDirectories: []string{filepath.FromSlash(tc.directory)},
			}
			data, err := json.Marshal(tx)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, recoveryJournalName), data, 0o600); err != nil {
				t.Fatal(err)
			}
			err = GuardMaintenance(directory)
			if tc.valid && (err == nil || !strings.Contains(err.Error(), "deployment has a pending recovery")) {
				t.Fatalf("valid pending transaction was not recognized: %v", err)
			}
			if !tc.valid && (err == nil || !strings.Contains(err.Error(), "unowned directory")) {
				t.Fatalf("unowned directory was not rejected: %v", err)
			}
		})
	}
}
