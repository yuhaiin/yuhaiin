package update

import (
	"context"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/update"
	"github.com/Asutorufa/yuhaiin/pkg/update/maintenance"
)

func (s *Service) operationStatus(local contract.Status, started time.Time) contract.Status {
	host, ok := s.installer.(ProtectedInstaller)
	if !ok || local.Running {
		return local
	}
	r, err := maintenance.Read(host.DataDirectory())
	if err != nil {
		return contract.Status{Stage: "error", Error: "durable update status is unavailable; inspect the offline update journal"}
	}
	if r == nil || (maintenance.Terminal(r.Phase) && r.Phase != "manual_recovery" && r.StartedAt.Before(started)) {
		return local
	}
	status := contract.Status{Running: !maintenance.Terminal(r.Phase), Stage: r.Phase, Operation: &r.OperationStatus}
	if r.Phase == "completed" {
		status.Progress = 100
	}
	if r.Phase == "failed" {
		status.Error = "update preparation failed; the source executable and deployment were preserved"
	}
	if r.ErrorCode == "executable_changed_review_required" {
		status.Error = "installed executable changed; preserve it and inspect offline update status before recovery"
	}
	if r.Phase == "manual_recovery" {
		status.Error = "update startup failed; stop the service and use the encrypted recovery point with the recorded source executable"
	}
	return status
}

func (s *Service) durableStatus(ctx context.Context) contract.Status {
	_ = ctx
	s.mu.RLock()
	local, started := s.status, s.statusStartedAt
	s.mu.RUnlock()
	return s.operationStatus(local, started)
}

// Admission reads the durable handoff before another download can hide it.
func (s *Service) guardPendingOperation() error {
	host, ok := s.installer.(ProtectedInstaller)
	if !ok {
		return nil
	}
	return maintenance.GuardAdmission(host.DataDirectory())
}
