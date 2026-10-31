package backup

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

type importMaintainerTest struct {
	recoveryMaintainerTest
	restores   int
	restoreErr error
}

func (m *importMaintainerTest) StartRestore(context.Context, string, time.Duration) error {
	m.restores++
	return m.restoreErr
}

func runtimeActivationFixture(t *testing.T) (*Backup, contractrecovery.ImportActivateRequest) {
	t.Helper()
	b, data, key, _ := recoveryImportFixture(t)
	item, err := b.UploadRecoveryImport(t.Context(), io.NopCloser(bytes.NewReader(data)), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	item, err = b.PreviewRecoveryImport(t.Context(), contractrecovery.ImportPreviewRequest{ID: item.ID, Mode: "clone", Identity: key.String()})
	if err != nil {
		t.Fatal(err)
	}
	preview := item.Preview
	request := contractrecovery.ImportActivateRequest{ID: item.ID, ConfirmPreviewID: item.PreviewID, ConfirmBackupID: preview.Manifest.ID, ConfirmSourceInstanceID: preview.Manifest.InstanceID,
		ConfirmTargetInstanceID: preview.TargetInstanceID, ConfirmResultInstanceID: preview.InstanceID, ConfirmMaintenance: true, ConfirmStartupChanges: true, ConfirmCloneEnrollment: true, ConfirmIdentityReplacement: true}
	return b, request
}

func TestWebActivationPersistsConsentAndDoesNotReplaceActiveOwners(t *testing.T) {
	b, request := runtimeActivationFixture(t)
	manager := new(importMaintainerTest)
	b.maintainer = manager
	before, err := os.ReadFile(filepath.Join(b.dir, "management-tls.pem"))
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		item, err := b.ActivateRecoveryImport(t.Context(), request)
		if err != nil || item.State != "activating" {
			t.Fatal("durable activation admission failed", err)
		}
	}
	if manager.restores != 1 {
		t.Fatal("retry replayed destructive maintenance", manager.restores)
	}
	row, err := b.store.RecoveryImport(t.Context(), request.ID)
	if err != nil || row.Activation == nil || *row.Activation != request {
		t.Fatal("independent helper did not receive exact-preview consent", err)
	}
	after, err := os.ReadFile(filepath.Join(b.dir, "management-tls.pem"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("request handler changed active TLS material", err)
	}
	if _, err := os.Lstat(filepath.Join(b.dir, ".recovery-transaction.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("request handler activated a file transaction", err)
	}
	status, err := b.RecoveryRestoreStatus(t.Context())
	if err != nil || status.PendingPreviewID != request.ConfirmPreviewID || status.Result != nil {
		t.Fatal("admission was described as completed restoration", err)
	}
	if err := b.Run(t.Context()); !errors.Is(err, contract.ErrBusy) {
		t.Fatal("a new configuration backup competed with restore admission", err)
	}
}

func TestWebActivationCancelRequiresIdleIndependentMaintenance(t *testing.T) {
	b, request := runtimeActivationFixture(t)
	b.maintainer = new(importMaintainerTest)
	if _, err := b.ActivateRecoveryImport(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	lease, err := lockfile.Acquire(filepath.Join(b.dir, ".recovery-maintenance.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if err := b.DiscardRecoveryImport(t.Context(), request.ID); err == nil {
		t.Fatal("active maintenance lost its staging")
	}
	row, err := b.store.RecoveryImport(t.Context(), request.ID)
	if err != nil || row.State != "activating" {
		t.Fatal("failed cancel changed the admission", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.DiscardRecoveryImport(t.Context(), request.ID); err != nil {
		t.Fatal(err)
	}
	if b.restoring.Load() {
		t.Fatal("cancelled unclaimed handoff kept the scheduler paused")
	}
	if _, err := os.Lstat(filepath.Join(b.dir, ".recovery-imports", request.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancel left private staging", err)
	}
}

func TestWebActivationLaunchErrorRetainsObservableCancelableAdmission(t *testing.T) {
	b, request := runtimeActivationFixture(t)
	b.maintainer = &importMaintainerTest{restoreErr: errors.New("fixture uncertain launch")}
	if item, err := b.ActivateRecoveryImport(t.Context(), request); err != nil || item.State != "activating" || item.ErrorCode != "launch_uncertain" {
		t.Fatal("uncertain launch hid the accepted durable admission", err)
	}
	status, err := b.RecoveryRestoreStatus(t.Context())
	if err != nil || status.PendingImportID != request.ID {
		t.Fatal("uncertain handoff became invisible", err)
	}
	// Expiry cannot remove staging while a helper may still own the handoff.
	row, err := b.store.RecoveryImport(t.Context(), request.ID)
	if err != nil {
		t.Fatal(err)
	}
	row.ExpiresAt = time.Now().Add(-time.Minute)
	if err := b.store.SaveRecoveryImport(t.Context(), row, "activating"); err != nil {
		t.Fatal(err)
	}
	if err := b.pruneRecoveryImports(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(b.dir, row.Stage)); err != nil {
		t.Fatal("expiry removed an admitted restore", err)
	}
	if err := b.DiscardRecoveryImport(t.Context(), request.ID); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreOutcomeOverridesItsStaleAdmissionAfterCleanupFailure(t *testing.T) {
	for _, state := range []string{"committed", "rolled_back"} {
		t.Run(state, func(t *testing.T) {
			b, request := runtimeActivationFixture(t)
			b.maintainer = new(importMaintainerTest)
			if _, err := b.ActivateRecoveryImport(t.Context(), request); err != nil {
				t.Fatal(err)
			}
			row, err := b.store.RecoveryImport(t.Context(), request.ID)
			if err != nil {
				t.Fatal(err)
			}
			result := contractrecovery.RestoreResult{BackupID: request.ConfirmBackupID, TransactionID: request.ConfirmPreviewID, InstanceID: request.ConfirmResultInstanceID, RecoveryPoint: ".recovery-point-" + request.ConfirmPreviewID, State: state, Runtime: row.Preview.Runtime}
			data, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(b.dir, ".recovery-last-result.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			actual, err := b.RecoveryRestoreStatus(t.Context())
			if err != nil || actual.Result == nil || actual.Result.State != state || actual.PendingImportID != "" || b.restoring.Load() {
				t.Fatal("stale admission hid authoritative file recovery", err)
			}
		})
	}
}

func TestRestoreAdmissionCannotRaceAnOwnedUpdateLease(t *testing.T) {
	b, request := runtimeActivationFixture(t)
	manager := new(importMaintainerTest)
	b.maintainer = manager
	lease, err := lockfile.Acquire(filepath.Join(b.dir, ".recovery-maintenance.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if _, err := b.ActivateRecoveryImport(t.Context(), request); !errors.Is(err, contract.ErrBusy) {
		t.Fatal("restore admission raced a binary update/capture helper", err)
	}
	item, err := b.store.RecoveryImport(t.Context(), request.ID)
	if err != nil || item.State != "previewed" || item.Activation != nil || manager.restores != 0 {
		t.Fatal("rejected handoff was nevertheless persisted/launched", err)
	}
}
