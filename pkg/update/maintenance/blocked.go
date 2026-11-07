package maintenance

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/update/compatibility"
)

// StartupBlockedError is returned when a terminal update journal does not
// authorize this executable. No database has been opened. A service manager
// restart cannot change the outcome, so callers should wait for the journal,
// adoption record or executable to change instead of exiting in a loop.
type StartupBlockedError struct {
	OperationID string
	Phase       string
	ErrorCode   string
	// Executable is recorded_source, recorded_target, adopted, unrecorded
	// or unreadable. It is diagnostic only and never grants admission.
	Executable string
	SHA256     string
	Reason     error
	NextSteps  []string
}

func (e *StartupBlockedError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "update operation %s (%s/%s) does not authorize this executable", e.OperationID, e.Phase, e.ErrorCode)
	if e.SHA256 != "" {
		fmt.Fprintf(&b, " (%s sha256 %s)", e.Executable, e.SHA256)
	}
	if e.Reason != nil {
		fmt.Fprintf(&b, ": %v", e.Reason)
	}
	b.WriteString("; databases were not opened and the service waits instead of restarting")
	for i, step := range e.NextSteps {
		fmt.Fprintf(&b, "\n  %d. %s", i+1, step)
	}
	return b.String()
}
func (e *StartupBlockedError) Unwrap() error { return e.Reason }

func blockedStartup(ctx context.Context, directory, executable string, r *Record, reason error) error {
	e := &StartupBlockedError{OperationID: r.ID, Phase: r.Phase, ErrorCode: r.ErrorCode, Executable: "unreadable", Reason: reason, NextSteps: RecoverySteps(directory, r)}
	if observed, err := compatibility.Describe(ctx, executable, r.Source.Platform, r.Source.Architecture); err == nil {
		e.SHA256 = observed.SHA256
		e.Executable = "unrecorded"
		switch observed.SHA256 {
		case r.SourceSHA256:
			e.Executable = "recorded_source"
		case r.TargetSHA256:
			e.Executable = "recorded_target"
		}
		if a, err := ReadAdoption(directory); err == nil && a != nil && a.OperationID == r.ID && a.Executable.SHA256 == observed.SHA256 {
			e.Executable = "adopted"
		}
	}
	return e
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func serviceStopCommand() string {
	switch runtime.GOOS {
	case "darwin":
		return "sudo launchctl bootout system /Library/LaunchDaemons/com.asutorufa.yuhaiin.plist"
	case "linux":
		return "sudo systemctl stop yuhaiin"
	default:
		return "stop the installed yuhaiin service"
	}
}

// RecoverySteps names concrete operator actions for a terminal operation.
// Preparation failures may adopt a verified binary; any operation which may
// have started the target keeps the paired archive/source restoration.
func RecoverySteps(directory string, r *Record) []string {
	if r == nil {
		return nil
	}
	dir := shellQuote(directory)
	target := shellQuote(r.TargetPath)
	status := fmt.Sprintf("Inspect the operation: %s update-status -path %s", target, dir)
	source := filepath.Join(directory, "update", "versions", r.SourceSHA256+".bin")
	reinstall := fmt.Sprintf("Or reinstall the recorded source executable (sha256 %s), for example %s if present, verify its digest, then copy it to %s with mode 0755", r.SourceSHA256, shellQuote(source), target)
	switch {
	case PreparationFailure(r):
		return []string{
			status,
			fmt.Sprintf("To keep the manually installed executable, run it once as root: sudo %s update-adopt -path %s (add -dry-run to only check). It reads the database schemas read-only and accepts only a binary that needs no migration; the waiting service then restarts by itself", target, dir),
			reinstall,
			"A binary that requires a database migration must not be adopted: reinstall the source and repeat the update through the protected Web UI update with a recovery point",
		}
	case r.Phase == "manual_recovery":
		point := "your own verified full offline archive (this update recorded no recovery point)"
		if r.BackupJobID != "" {
			point = "the matching recovery point " + shellQuote(filepath.Join(directory, ".recovery-archives", r.BackupJobID+".yhb"))
		}
		return []string{
			status,
			"Keep the service stopped: " + serviceStopCommand(),
			fmt.Sprintf("Restore %s with the recorded source executable (sha256 %s) in original mode, as described in docs/recovery-archive.md; executable adoption is not available because the target may have migrated the databases", point, r.SourceSHA256),
		}
	default:
		return []string{status, reinstall}
	}
}

type fileState struct {
	info os.FileInfo
	err  bool
}

func observeFile(path string, follow bool) fileState {
	var info os.FileInfo
	var err error
	if follow {
		info, err = os.Stat(path)
	} else {
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fileState{err: true}
	}
	return fileState{info: info}
}
func (a fileState) equal(b fileState) bool {
	if a.err || b.err {
		return a.err == b.err
	}
	return os.SameFile(a.info, b.info) && a.info.Size() == b.info.Size() && a.info.ModTime().Equal(b.info.ModTime()) && a.info.Mode() == b.info.Mode()
}

// WaitStartupChange blocks a refused startup until the update journal, the
// adoption record or the executable changes, then returns nil so the service
// manager can re-evaluate a fresh process. Cancellation returns ctx.Err().
// Only metadata is polled; nothing is hashed and no database is opened.
func WaitStartupChange(ctx context.Context, directory, executable string, interval time.Duration) error {
	paths := []struct {
		path   string
		follow bool
	}{{filepath.Join(directory, journalName), false}, {filepath.Join(directory, adoptionName), false}, {executable, true}}
	initial := make([]fileState, len(paths))
	for i, p := range paths {
		initial[i] = observeFile(p.path, p.follow)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		for i, p := range paths {
			if !initial[i].equal(observeFile(p.path, p.follow)) {
				return nil
			}
		}
	}
}

// IsStartupBlocked reports a refusal which a restart alone cannot resolve.
func IsStartupBlocked(err error) (*StartupBlockedError, bool) {
	return errors.AsType[*StartupBlockedError](err)
}
