//go:build linux

package recoverycmd

import (
	"context"
	"errors"
	"time"

	"github.com/Asutorufa/yuhaiin/cmd/yuhaiin/internal/servicehost"
	"github.com/Asutorufa/yuhaiin/pkg/app/backup/recovery"
)

func Capture(args []string) error {
	if len(args) != 2 {
		return errors.New("recovery-maintenance requires deployment directory and job identifier")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Hour+2*time.Minute)
	defer cancel()
	return recovery.Capture(ctx, args[0], args[1], servicehost.Service{})
}

func RestartCapture(args []string) error {
	if len(args) != 2 {
		return errors.New("recovery-maintenance-restart requires deployment directory and job identifier")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return recovery.RestartService(ctx, args[0], args[1], servicehost.Service{})
}

func Restore(args []string) error {
	if len(args) != 2 {
		return errors.New("recovery-restore requires deployment directory and import identifier")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	return recovery.RestoreImport(ctx, args[0], args[1], servicehost.Service{})
}

func RestartRestore(args []string) error {
	if len(args) != 2 {
		return errors.New("recovery-restore-restart requires deployment directory and import identifier")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return recovery.RestartImportService(ctx, args[0], args[1], servicehost.Service{})
}
