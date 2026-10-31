package update

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"uuid"

	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/update"
	"github.com/Asutorufa/yuhaiin/pkg/update/compatibility"
	"github.com/Asutorufa/yuhaiin/pkg/update/maintenance"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

type protectionFixture struct {
	directory, executable string
	readiness             contract.RecoveryReadiness
	launchError           error
}

func (h *protectionFixture) Supported() (bool, string) { return true, "" }
func (h *protectionFixture) Start(context.Context, string) error {
	return errors.New("legacy installer must not run")
}
func (h *protectionFixture) ProtectedUpdateSupported() (bool, string)     { return true, "" }
func (h *protectionFixture) DataDirectory() string                        { return h.directory }
func (h *protectionFixture) ActiveExecutable() string                     { return h.executable }
func (h *protectionFixture) StartProtected(context.Context, string) error { return h.launchError }
func (h *protectionFixture) UpdateRecoveryReadiness(context.Context) (contract.RecoveryReadiness, error) {
	return h.readiness, nil
}
func (h *protectionFixture) QueueUpdateRecovery(context.Context) (contractrecovery.Backup, error) {
	return contractrecovery.Backup{}, errors.New("unprotected fixture must not enqueue")
}
func (h *protectionFixture) CancelUpdateRecovery(context.Context, string) error { return nil }

func TestProtectedHandoffRetainsAmbiguousAdmissionAndOnlyCancelsBeforeClaim(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("installed protected update host uses Linux")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	h := &protectionFixture{directory: t.TempDir(), executable: self, readiness: contract.RecoveryReadiness{Enabled: false, Supported: true, Ready: true}, launchError: errors.New("lost launch response")}
	s := NewService(Options{Installer: h, Recovery: h})
	source, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	stage, err := os.CreateTemp(filepath.Dir(self), "yuhaiin-update-fixture-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(stage.Name())
	if _, err := io.Copy(stage, source); err != nil {
		t.Fatal(err)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	m, err := compatibility.Describe(t.Context(), stage.Name(), runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New().String()
	legacy := m
	legacy.UpdateGuard = 0
	if err := s.installPrepared(t.Context(), stage.Name(), legacy, id); err == nil {
		t.Fatal("old target without startup receipts admitted")
	}
	if err := s.installPrepared(t.Context(), stage.Name(), m, id); !errors.Is(err, errProtectedHandoffUncertain) {
		t.Fatal("lost acknowledgement was treated as a rejected update", err)
	}
	if _, err := os.Stat(stage.Name()); err != nil {
		t.Fatal("ambiguous handoff deleted live staging", err)
	}
	record, err := maintenance.Read(h.directory)
	if err != nil || record.ID != id || record.Phase != "prepared" {
		t.Fatal("admission lost", err)
	}
	if err := s.guardPendingOperation(); err == nil {
		t.Fatal("pending handoff permitted another update")
	}
	lease, err := lockfile.Acquire(filepath.Join(h.directory, ".recovery-maintenance.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Cancel(t.Context(), id); err == nil {
		t.Fatal("claimed maintenance was cancelled")
	}
	_ = lease.Close()
	if err := s.Cancel(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	if err := s.Cancel(t.Context(), id); err != nil {
		t.Fatal("cancellation cleanup is not retryable", err)
	}
	if _, err := os.Stat(stage.Name()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled staging remains", err)
	}
	if err := s.guardPendingOperation(); err != nil {
		t.Fatal("cancelled admission retained an indefinite block", err)
	}
	// A newer download error must not be hidden by an older terminal journal.
	s.status = contract.Status{Stage: "error", Error: "new download failed"}
	s.statusStartedAt = time.Now().UTC().Add(time.Second)
	status := s.Status(t.Context())
	if status.Error != "new download failed" || status.Operation != nil {
		t.Fatal("stale journal hid new failure", status)
	}
}

func TestUpdateConsentRequiresProtectionForMigrations(t *testing.T) {
	h := &protectionFixture{readiness: contract.RecoveryReadiness{Enabled: true, Supported: true, Ready: true}}
	s := NewService(Options{Installer: h, Recovery: h})
	complete := contract.ApplyRequest{ConfirmMaintenance: true, ConfirmManualRecovery: true, ConfirmNoRecoveryPoint: true}
	for _, state := range []string{"compatible", "migration_required", "incompatible", "unknown"} {
		status := contract.CompatibilityStatus{State: state}
		if err := s.validateUpdateConsent(t.Context(), status, contract.ApplyRequest{}); err == nil {
			t.Fatal("missing maintenance consent accepted", state)
		}
		err := s.validateUpdateConsent(t.Context(), status, complete)
		if (err == nil) != (state == "compatible" || state == "migration_required") {
			t.Fatal("wrong protected admission", state, err)
		}
	}
	h.readiness.Enabled = false
	if err := s.validateUpdateConsent(t.Context(), contract.CompatibilityStatus{State: "migration_required"}, complete); err == nil {
		t.Fatal("unprotected migration accepted")
	}
	if err := s.validateUpdateConsent(t.Context(), contract.CompatibilityStatus{State: "compatible"}, complete); err != nil {
		t.Fatal(err)
	}
	complete.OperationID = "not-an-operation"
	if err := s.validateUpdateConsent(t.Context(), contract.CompatibilityStatus{State: "compatible"}, complete); err == nil {
		t.Fatal("malformed operation ID accepted")
	}
}
