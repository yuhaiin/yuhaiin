package recovery

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"syscall"

	"github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/backupfs"
)

// captureFailure retains the detailed cause for offline logs. Only allowlisted
// stage/code values are persisted in public history, never paths or key bytes.
type captureFailure struct {
	stage string
	cause error
}

func (e *captureFailure) Error() string { return e.cause.Error() }
func (e *captureFailure) Unwrap() error { return e.cause }

func captureFailureDetails(err error) (string, string) {
	stage := "capture"
	if failure, ok := errors.AsType[*captureFailure](err); ok {
		stage = failure.stage
	}
	switch {
	case errors.Is(err, context.Canceled):
		return stage, "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return stage, "timeout"
	case errors.Is(err, fs.ErrPermission):
		return stage, "permission_denied"
	case errors.Is(err, syscall.ENOSPC), errors.Is(err, backupfs.ErrInsufficientStagingSpace):
		return stage, "insufficient_space"
	case errors.Is(err, fs.ErrNotExist):
		return stage, "required_file_missing"
	case errors.Is(err, syscall.EIO), errors.Is(err, io.ErrUnexpectedEOF):
		return stage, "io_error"
	}
	return stage, "invalid_or_unsafe_input"
}
