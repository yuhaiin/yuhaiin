package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
)

func (a v2API) recoveryBackups(ctx context.Context, _ *emptyRequest) (*contract.RecoveryBackupStatus, error) {
	owner, ok := a.services.Backup.(RecoveryBackupController)
	if !ok {
		return nil, unavailable("recovery backup controller is unavailable")
	}
	return pointer(owner.RecoveryBackups(ctx))
}

func (a v2API) createRecoveryBackup(ctx context.Context, request *contract.RecoveryBackupRequest) (*contract.RecoveryBackup, error) {
	owner, ok := a.services.Backup.(RecoveryBackupController)
	if !ok {
		return nil, unavailable("recovery backup controller is unavailable")
	}
	value, err := owner.CreateRecoveryBackup(ctx, *request)
	if err != nil {
		return nil, badRequest(err)
	}
	return &value, nil
}

// Downloads stay outside JSON RPC and stream directly from a private managed
// file. The route retains BackupManage authorization and never accepts a path.
func recoveryBackupDownload(services V2Services) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		owner, ok := services.Backup.(RecoveryBackupController)
		if !ok {
			return writeRPCError(w, unavailable("recovery backup controller is unavailable"))
		}
		file, item, err := owner.OpenRecoveryBackup(r.Context(), r.PathValue("id"))
		if err != nil {
			if errors.Is(err, contract.ErrBusy) {
				return writeRPCError(w, badRequest(err))
			}
			return writeRPCError(w, notFound(err))
		}
		defer file.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(item.ID+".yhb"))
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		http.ServeContent(w, r, item.ID+".yhb", item.CreatedAt, file)
		return nil
	}
}

type recoveryBackupDeleteRequest struct {
	ID      string `json:"id"`
	Confirm bool   `json:"confirm"`
}

func (a v2API) deleteRecoveryBackup(ctx context.Context, request *recoveryBackupDeleteRequest) (*emptyResponse, error) {
	owner, ok := a.services.Backup.(RecoveryBackupController)
	if !ok {
		return nil, unavailable("recovery backup controller is unavailable")
	}
	if !request.Confirm {
		return nil, badRequest(errors.New("backup deletion requires explicit confirmation"))
	}
	if err := owner.DeleteRecoveryBackup(ctx, request.ID); err != nil {
		return nil, badRequest(err)
	}
	return &emptyResponse{}, nil
}

func (a v2API) retryRecoveryBackup(ctx context.Context, request *idRequest) (*emptyResponse, error) {
	owner, ok := a.services.Backup.(RecoveryBackupController)
	if !ok {
		return nil, unavailable("recovery backup controller is unavailable")
	}
	if err := owner.RetryRecoveryBackup(ctx, request.ID); err != nil {
		return nil, badRequest(err)
	}
	return &emptyResponse{}, nil
}

func (a v2API) verifyRecoveryBackup(ctx context.Context, request *contract.RecoveryVerifyRequest) (*contract.RecoveryManifest, error) {
	owner, ok := a.services.Backup.(RecoveryBackupController)
	if !ok {
		return nil, unavailable("recovery backup controller is unavailable")
	}
	manifest, err := owner.VerifyRecoveryBackup(ctx, *request)
	if err != nil {
		return nil, badRequest(err)
	}
	return &manifest, nil
}
