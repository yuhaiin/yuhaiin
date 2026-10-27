package httpapi

import (
	"context"
	"errors"
	"net/http"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/s3"
)

func (a v2API) recoveryImports(ctx context.Context, _ *emptyRequest) (*[]contract.RecoveryImport, error) {
	owner, ok := a.services.Backup.(RecoveryImportController)
	if !ok {
		return nil, unavailable("recovery import controller is unavailable")
	}
	return pointer(owner.RecoveryImports(ctx))
}

func (a v2API) recoveryRestoreStatus(ctx context.Context, _ *emptyRequest) (*contract.RecoveryRestoreStatus, error) {
	owner, ok := a.services.Backup.(RecoveryRestoreReporter)
	if !ok {
		return nil, unavailable("recovery restore status is unavailable")
	}
	return pointer(owner.RecoveryRestoreStatus(ctx))
}

func recoveryImportUpload(services V2Services) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		owner, ok := services.Backup.(RecoveryImportController)
		if !ok {
			return writeRPCError(w, unavailable("recovery import controller is unavailable"))
		}
		if r.Header.Get("Content-Type") != "application/octet-stream" {
			return writeError(w, http.StatusUnsupportedMediaType, "invalid_archive_type", "upload the encrypted archive as application/octet-stream")
		}
		if r.ContentLength > s3.MaxObjectBytes {
			return writeError(w, http.StatusRequestEntityTooLarge, "archive_too_large", "encrypted recovery upload exceeds 100 GiB")
		}
		r.Body = http.MaxBytesReader(w, r.Body, s3.MaxObjectBytes)
		item, err := owner.UploadRecoveryImport(r.Context(), r.Body, r.ContentLength)
		if err != nil {
			if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
				return writeError(w, http.StatusRequestEntityTooLarge, "archive_too_large", "encrypted recovery upload exceeds 100 GiB")
			}
			return writeRPCError(w, badRequest(err))
		}
		w.Header().Set("Cache-Control", "no-store")
		return writeJSON(w, http.StatusOK, item)
	}
}

func (a v2API) previewRecoveryImport(ctx context.Context, request *contract.RecoveryImportPreviewRequest) (*contract.RecoveryImport, error) {
	owner, ok := a.services.Backup.(RecoveryImportController)
	if !ok {
		return nil, unavailable("recovery import controller is unavailable")
	}
	item, err := owner.PreviewRecoveryImport(ctx, *request)
	if err != nil {
		return nil, badRequest(err)
	}
	return &item, nil
}

func (a v2API) discardRecoveryImport(ctx context.Context, request *recoveryBackupDeleteRequest) (*emptyResponse, error) {
	owner, ok := a.services.Backup.(RecoveryImportController)
	if !ok {
		return nil, unavailable("recovery import controller is unavailable")
	}
	if !request.Confirm {
		return nil, badRequest(errors.New("discarding a recovery import requires confirmation"))
	}
	if err := owner.DiscardRecoveryImport(ctx, request.ID); err != nil {
		return nil, badRequest(err)
	}
	return &emptyResponse{}, nil
}
