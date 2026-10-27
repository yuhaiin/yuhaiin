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
