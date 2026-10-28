package maintenance

import (
	"context"
	"errors"
	"os"
	"slices"
	"time"
)

// Startup is bound to one journal and executable. Complete is called only after
// real database/inbound/Gateway and pinned local management-listener checks.
type Startup struct {
	directory, id string
	recovered     bool
}

func PrepareStartup(ctx context.Context, directory, executable, restoredBackupID, restoredInstanceID string) (*Startup, error) {
	r, err := Read(directory)
	if err != nil || r == nil {
		return nil, err
	}
	switch r.Phase {
	case "completed", "recovered":
		return nil, nil
	case "failed":
		return nil, verify(ctx, executable, r.Source)
	case "starting", "healthy":
		if err := verify(ctx, executable, r.Target); err != nil {
			return nil, err
		}
		return &Startup{directory: directory, id: r.ID}, nil
	case "manual_recovery":
		if r.BackupID == "" || restoredBackupID != r.BackupID || r.SourceInstanceID == "" || restoredInstanceID != r.SourceInstanceID {
			return nil, errors.New("update requires authenticated offline restoration of its matching recovery point")
		}
		if err := verify(ctx, executable, r.Source); err != nil {
			return nil, errors.New("update recovery requires the recorded source executable and matching database archive")
		}
		return &Startup{directory: directory, id: r.ID, recovered: true}, nil
	default:
		return nil, errors.New("update maintenance has not authorized this service startup")
	}
}
func (s *Startup) Complete(ctx context.Context, address string, certificate []byte) error {
	if s == nil {
		return nil
	}
	return change(ctx, s.directory, s.id, func(r *Record) error {
		if s.recovered {
			if r.Phase != "manual_recovery" {
				return errors.New("manual update recovery changed")
			}
			r.Phase, r.ErrorCode, r.CompletedAt = "recovered", "", time.Now().UTC()
			return nil
		}
		if r.Phase != "starting" && r.Phase != "healthy" {
			return errors.New("update startup admission changed")
		}
		r.Phase, r.ReadyPID, r.ReadyAt = "healthy", os.Getpid(), time.Now().UTC()
		r.ReadyAddress, r.ReadyCertificate = address, slices.Clone(certificate)
		return nil
	})
}

// AwaitVerification keeps certificate renewal behind the independent helper's
// pinned listener check. A startup receipt alone is not its acknowledgement;
// replacing the leaf while that check is pending would invalidate the pin.
func (s *Startup) AwaitVerification(ctx context.Context) error {
	if s == nil || s.recovered {
		return nil
	}
	timer := time.NewTicker(250 * time.Millisecond)
	defer timer.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		r, err := Read(s.directory)
		if err != nil {
			return err
		}
		if r == nil || r.ID != s.id || r.ReadyPID != os.Getpid() {
			return errors.New("update verification no longer owns this startup")
		}
		if r.Phase == "completed" {
			return nil
		}
		if r.Phase != "healthy" {
			return errors.New("independent update verification did not complete")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}
