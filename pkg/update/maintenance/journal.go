// Package maintenance coordinates an installed update with the existing recovery
// archive owner and a durable, bounded startup receipt. It owns no database.
package maintenance

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"
	"uuid"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/update"
	"github.com/Asutorufa/yuhaiin/pkg/update/compatibility"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicfile"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

const journalName = ".update-operation.json"
const maxJournalBytes = 2 << 20

type Record struct {
	contract.OperationStatus
	Version          int                    `json:"version"`
	Source           compatibility.Manifest `json:"source"`
	Target           compatibility.Manifest `json:"target"`
	TargetPath       string                 `json:"targetPath"`
	StagedPath       string                 `json:"stagedPath"`
	SourceInstanceID string                 `json:"sourceInstanceId,omitempty"`
	SourceVersion    string                 `json:"sourceVersion"`
	SourceCommit     string                 `json:"sourceCommit"`
	AllowNoPoint     bool                   `json:"allowNoPoint,omitzero"`
	ReadyAddress     string                 `json:"readyAddress,omitempty"`
	ReadyCertificate []byte                 `json:"readyCertificate,omitempty"`
	ReadyPID         int                    `json:"readyPid,omitzero"`
	ReadyAt          time.Time              `json:"readyAt,omitzero"`
}

func Terminal(phase string) bool {
	return slices.Contains([]string{"completed", "failed", "manual_recovery", "recovered"}, phase)
}
func validID(id string) bool {
	v, err := uuid.Parse(id)
	return err == nil && v != (uuid.UUID{}) && v.String() == id
}
func (r Record) validate() error {
	if r.Version != 1 || !validID(r.ID) || r.StartedAt.IsZero() || !slices.Contains([]string{"prepared", "capturing", "backup_ready", "swapping", "starting", "healthy", "completed", "failed", "manual_recovery", "recovered"}, r.Phase) {
		return errors.New("invalid update operation")
	}
	if err := r.Source.Validate(); err != nil {
		return err
	}
	if err := r.Target.Validate(); err != nil {
		return err
	}
	if r.SourceSHA256 != r.Source.SHA256 || r.TargetSHA256 != r.Target.SHA256 || !filepath.IsAbs(r.TargetPath) || !filepath.IsAbs(r.StagedPath) || filepath.Dir(r.TargetPath) != filepath.Dir(r.StagedPath) {
		return errors.New("invalid update executable ownership")
	}
	name := filepath.Base(r.StagedPath)
	if !strings.HasPrefix(name, "yuhaiin-update-") && !strings.HasPrefix(name, ".yuhaiin-rollback-") {
		return errors.New("invalid update staging namespace")
	}
	if r.BackupJobID != "" && !validID(r.BackupJobID) {
		return errors.New("invalid update backup job")
	}
	if (r.SourceInstanceID != "" && !validID(r.SourceInstanceID)) || (r.BackupID != "" && !validID(r.BackupID)) {
		return errors.New("invalid update backup identity")
	}
	if r.BackupJobID == "" && !r.AllowNoPoint {
		return errors.New("update has no recovery point or explicit opt-out")
	}
	if len(r.ErrorCode) > 64 || r.ReadyPID < 0 || len(r.ReadyAddress) > 256 || len(r.ReadyCertificate) > 64<<10 {
		return errors.New("invalid update outcome")
	}
	return nil
}

func Read(directory string) (*Record, error) {
	path := filepath.Join(directory, journalName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxJournalBytes || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return nil, errors.New("invalid private update journal")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxJournalBytes+1))
	if err != nil || len(data) > maxJournalBytes {
		return nil, errors.New("update journal exceeds its limit")
	}
	var record Record
	if err := json.Unmarshal(data, &record, json.RejectUnknownMembers(true)); err != nil {
		return nil, errors.New("invalid update journal JSON")
	}
	if err := record.validate(); err != nil {
		return nil, err
	}
	return &record, nil
}

func save(directory string, r Record) error {
	if err := r.validate(); err != nil {
		return err
	}
	data, err := json.Marshal(r)
	if err != nil || len(data) > maxJournalBytes {
		return errors.New("update journal exceeds its limit")
	}
	path := filepath.Join(directory, journalName)
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("update journal must be a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := atomicfile.WriteFile(path, data, 0600); err != nil {
		return err
	}
	return syncDirectory(directory)
}
func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return errors.ErrUnsupported
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func withJournalLock(ctx context.Context, directory string, fn func() error) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for {
		owner, err := lockfile.Acquire(filepath.Join(directory, ".update-operation.lock"))
		if err == nil {
			defer owner.Close()
			return fn()
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}
func Begin(ctx context.Context, directory string, r Record) error {
	return withJournalLock(ctx, directory, func() error {
		old, err := Read(directory)
		if err != nil {
			return err
		}
		if old != nil && (old.ID == r.ID || !Terminal(old.Phase) || old.Phase == "manual_recovery") {
			return errors.New("an update operation is already pending")
		}
		if r.ID == "" {
			r.ID = uuid.New().String()
		}
		r.Version, r.Phase, r.StartedAt = 1, "prepared", time.Now().UTC()
		r.SourceSHA256, r.TargetSHA256 = r.Source.SHA256, r.Target.SHA256
		return save(directory, r)
	})
}
func change(ctx context.Context, directory, id string, fn func(*Record) error) error {
	return withJournalLock(ctx, directory, func() error {
		record, err := Read(directory)
		if err != nil {
			return err
		}
		if record == nil || record.ID != id {
			return errors.New("update operation changed")
		}
		if err := fn(record); err != nil {
			return err
		}
		return save(directory, *record)
	})
}
func SetPhase(ctx context.Context, directory, id, phase, code string) error {
	return change(ctx, directory, id, func(r *Record) error {
		allowed := map[string][]string{
			"prepared":        {"capturing", "backup_ready", "failed"},
			"capturing":       {"backup_ready", "failed"},
			"backup_ready":    {"swapping", "failed"},
			"swapping":        {"starting", "failed"},
			"starting":        {"healthy", "manual_recovery"},
			"healthy":         {"completed", "manual_recovery"},
			"manual_recovery": {"recovered"},
		}
		if r.Phase != phase && !slices.Contains(allowed[r.Phase], phase) {
			return errors.New("invalid update state transition")
		}
		r.Phase, r.ErrorCode = phase, code
		if Terminal(phase) {
			r.CompletedAt = time.Now().UTC()
		}
		return nil
	})
}
func ActiveBackup(directory string) (string, error) {
	r, err := Read(directory)
	if err != nil || r == nil {
		return "", err
	}
	if !Terminal(r.Phase) || r.Phase == "manual_recovery" {
		return r.BackupJobID, nil
	}
	return "", nil
}

// GuardAdmission protects a pending handoff even before its helper claims the
// maintenance lease. Callers hold that lease across their own admission.
func GuardAdmission(directory string) error {
	r, err := Read(directory)
	if err != nil {
		return err
	}
	if r != nil && (!Terminal(r.Phase) || r.Phase == "manual_recovery") {
		return errors.New("an update operation requires completion, cancellation or offline recovery")
	}
	return nil
}
