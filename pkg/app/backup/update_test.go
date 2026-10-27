package backup

import (
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"uuid"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/update/compatibility"
	"github.com/Asutorufa/yuhaiin/pkg/update/maintenance"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

func TestUpdatePointCannotBeDeletedOrExpiredDuringUnresolvedRecovery(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("protected updates currently use Linux installed services")
	}
	b, owner := recoveryTransferBackup(t, func(http.ResponseWriter, *http.Request) { t.Error("local retention used a network") })
	old := queuedArchiveFixture(t, b, "local", time.Now().Add(-72*time.Hour))
	_ = queuedArchiveFixture(t, b, "local", time.Now())
	options, err := owner.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	options.Recovery = &contract.RecoveryPolicy{Target: "local", Recipient: old.Policy.Recipient, KeepCount: 1, KeepDays: 1}
	if err := owner.Save(t.Context(), options); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	m, err := compatibility.Describe(t.Context(), executable, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New().String()
	if err := maintenance.Begin(t.Context(), b.dir, maintenance.Record{ID: id, Source: m, Target: m, TargetPath: executable, StagedPath: filepath.Join(filepath.Dir(executable), "yuhaiin-update-fixture"), BackupJobID: old.ID}); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"prepared", "capturing", "backup_ready", "swapping", "starting", "manual_recovery"} {
		if phase != "prepared" {
			if err := maintenance.SetPhase(t.Context(), b.dir, id, phase, ""); err != nil {
				t.Fatal(err)
			}
		}
		if err := b.DeleteRecoveryBackup(t.Context(), old.ID); err == nil {
			t.Fatal("required update point deleted", phase)
		}
		ids, err := b.recoveryRetentionPlan(t.Context())
		if err != nil || len(ids) != 0 {
			t.Fatal("required update point expired", phase, ids, err)
		}
	}
	if err := maintenance.SetPhase(t.Context(), b.dir, id, "recovered", ""); err != nil {
		t.Fatal(err)
	}
	ids, err := b.recoveryRetentionPlan(t.Context())
	if err != nil || len(ids) != 1 || ids[0] != old.ID {
		t.Fatal("resolved update point was retained forever", ids, err)
	}
	lease, err := lockfile.Acquire(filepath.Join(b.dir, ".recovery-maintenance.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.DeleteRecoveryBackup(t.Context(), old.ID); err == nil {
		t.Fatal("deletion raced maintenance")
	}
	_ = lease.Close()
	if err := b.DeleteRecoveryBackup(t.Context(), old.ID); err != nil {
		t.Fatal(err)
	}
}
