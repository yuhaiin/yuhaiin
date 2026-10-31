package backup

import (
	"context"
	"time"
)

// RecoveryMaintainer is supplied by the installed-service host. It launches an
// independent helper; stopping the server must not cancel its own snapshot job.
type RecoveryMaintainer interface {
	Supported() (bool, string)
	StartRecovery(context.Context, string, time.Duration) error
}

// RecoveryRestorer is supported by hosts that can supervise real startup checks
// and restart the original deployment after an interrupted Web restore.
type RecoveryRestorer interface {
	StartRestore(context.Context, string, time.Duration) error
}
