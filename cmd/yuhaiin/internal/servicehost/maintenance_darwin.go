//go:build darwin

package servicehost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"uuid"

	backupapp "github.com/Asutorufa/yuhaiin/pkg/app/backup"
	"github.com/Asutorufa/yuhaiin/pkg/update/maintenance"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicfile"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

const (
	launchdTaskPrefix     = "com.asutorufa.yuhaiin.maintenance."
	launchdTaskDirectory  = ".recovery-launchd"
	launchdServiceLabel   = "com.asutorufa.yuhaiin"
	maxLaunchdHelperBytes = 512 << 20
)

var errLaunchdJobMissing = errors.New("launchd job is not loaded")

type launchdSettings struct {
	domain, plistDirectory string
	owner                  uint32
	environment            map[string]string
}

func systemLaunchd() launchdSettings {
	return launchdSettings{domain: "system", plistDirectory: "/Library/LaunchDaemons", owner: 0}
}

func launchctl(ctx context.Context, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, "/bin/launchctl", args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("launchctl %s: %w: %s", args[0], err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func plistJSON(ctx context.Context, path string) ([]byte, error) {
	// plutil also accepts installed XML with a leading newline and binary plists.
	return exec.CommandContext(ctx, "/usr/bin/plutil", "-convert", "json", "-o", "-", path).Output()
}

func checkLaunchdPath(path string, owner uint32, directory bool, private bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	mask := os.FileMode(0022)
	if private {
		mask = 0077
	}
	if !ok || stat.Uid != owner || info.Mode().Perm()&mask != 0 ||
		(directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		return errors.New("launchd maintenance requires owned, non-writable service files and private job directories")
	}
	return nil
}

// A system LaunchDaemon executes its helper by absolute path. Protect every
// directory in the path against replacement, including writes granted by ACLs.
func checkSystemLaunchdTree(ctx context.Context, files []string, directories ...string) error {
	args := []string{"-lbde"}
	seen := map[string]bool{}
	for _, file := range files {
		if !filepath.IsAbs(file) {
			return errors.New("system launchd paths must be absolute")
		}
		if err := checkLaunchdPath(file, 0, false, false); err != nil {
			return err
		}
		if !seen[file] {
			args = append(args, file)
			seen[file] = true
			directories = append(directories, filepath.Dir(file))
		}
	}
	for _, directory := range directories {
		if !filepath.IsAbs(directory) {
			return errors.New("system launchd paths must be absolute")
		}
		for current := filepath.Clean(directory); !seen[current]; current = filepath.Dir(current) {
			if err := checkLaunchdPath(current, 0, true, false); err != nil {
				return err
			}
			args = append(args, current)
			seen[current] = true
		}
	}
	out, err := exec.CommandContext(ctx, "/bin/ls", args...).Output()
	if err != nil {
		return err
	}
	// -e prints each ACL entry and marks the mode with '+'. -b escapes
	// control characters so a custom directory name cannot add a fake line.
	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if len(lines) != len(seen) {
		return errors.New("system launchd paths must not have extended ACLs")
	}
	for _, line := range lines {
		mode, _, _ := strings.Cut(line, " ")
		if strings.Contains(mode, "+") {
			return errors.New("system launchd paths must not have extended ACLs")
		}
	}
	return nil
}

type launchdService struct {
	settings                launchdSettings
	label, plist, directory string
}

func installedLaunchd(directory string) launchdService {
	return launchdService{settings: systemLaunchd(), label: launchdServiceLabel, plist: darwinSystemPlist, directory: directory}
}

func (s launchdService) executable(ctx context.Context) (string, error) {
	if err := checkLaunchdPath(s.plist, s.settings.owner, false, false); err != nil {
		return "", err
	}
	data, err := plistJSON(ctx, s.plist)
	if err != nil {
		return "", err
	}
	var p struct {
		Label, Program, UserName string
		ProgramArguments         []string
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return "", err
	}
	if p.Label != s.label || len(p.ProgramArguments) == 0 ||
		(p.Program != "" && p.Program != p.ProgramArguments[0]) ||
		(s.settings.owner == 0 && p.UserName != "" && p.UserName != "root") {
		return "", errors.New("installed launchd service identity differs")
	}
	executable := p.ProgramArguments[0]
	if !filepath.IsAbs(executable) {
		return "", errors.New("installed launchd executable must be absolute")
	}
	directory := "/Library/Application Support/yuhaiin"
	args := p.ProgramArguments[1:]
	if len(args) > 0 && args[0] == "run" {
		args = args[1:]
	}
	seen := false
	for i := 0; i < len(args); i++ {
		name, value, equal := strings.Cut(strings.TrimLeft(args[i], "-"), "=")
		if name != "path" && name != "p" {
			continue
		}
		if seen {
			return "", errors.New("ambiguous installed data directory")
		}
		seen = true
		if !equal {
			i++
			if i >= len(args) {
				return "", errors.New("missing installed data directory")
			}
			value = args[i]
		}
		directory = value
	}
	if !filepath.IsAbs(directory) {
		return "", errors.New("installed data directory must be absolute")
	}
	want, err := filepath.EvalSymlinks(s.directory)
	if err != nil {
		return "", err
	}
	got, err := filepath.EvalSymlinks(directory)
	if err != nil || got != want {
		return "", errors.New("installed launchd data directory differs")
	}
	return executable, nil
}

func launchdPID(ctx context.Context, target string) (int, error) {
	out, err := launchctl(ctx, "print", target)
	if err != nil {
		// launchctl documents 113 as "Could not find specified service".
		if exit, ok := errors.AsType[*exec.ExitError](err); ok && exit.ExitCode() == 113 {
			return 0, errLaunchdJobMissing
		}
		return 0, err
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "pid = "); ok {
			pid, err := strconv.Atoi(value)
			if err != nil || pid < 1 {
				return 0, errors.New("invalid launchd service PID")
			}
			return pid, nil
		}
	}
	return 0, nil // A loaded job may not have started its process yet.
}

func (s launchdService) stop(ctx context.Context) error {
	if _, err := s.executable(ctx); err != nil {
		return err
	}
	target := s.settings.domain + "/" + s.label
	pid, err := launchdPID(ctx, target)
	if err != nil {
		if errors.Is(err, errLaunchdJobMissing) {
			return nil
		}
		return err
	}
	if _, err := launchctl(ctx, "bootout", target); err != nil {
		return err
	}
	timer := time.NewTicker(100 * time.Millisecond)
	defer timer.Stop()
	deadline, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for pid > 0 {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return nil
		} else if err != nil && !errors.Is(err, syscall.EPERM) {
			return err
		}
		select {
		case <-deadline.Done():
			return errors.New("installed launchd process did not stop")
		case <-timer.C:
		}
	}
	return nil
}

func (s launchdService) start(ctx context.Context) error {
	executable, err := s.executable(ctx)
	if err != nil {
		return err
	}
	if err := checkLaunchdPath(executable, s.settings.owner, false, false); err != nil {
		return err
	}
	target := s.settings.domain + "/" + s.label
	pid, err := launchdPID(ctx, target)
	switch {
	case err == nil && pid > 0:
		return nil
	case err == nil:
		_, err = launchctl(ctx, "kickstart", target)
	case errors.Is(err, errLaunchdJobMissing):
		_, err = launchctl(ctx, "bootstrap", s.settings.domain, s.plist)
	}
	if err != nil {
		return err
	}
	deadline, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	timer := time.NewTicker(100 * time.Millisecond)
	defer timer.Stop()
	for {
		pid, err := launchdPID(deadline, target)
		if err != nil {
			return err
		}
		if pid > 0 {
			return nil
		}
		select {
		case <-deadline.Done():
			return fmt.Errorf("installed launchd process did not start: %w", deadline.Err())
		case <-timer.C:
		}
	}
}

// DarwinService is the installed host used under the update owner's lease.
type DarwinService struct{ Directory string }

func (s DarwinService) Stop(ctx context.Context) error {
	return installedLaunchd(s.Directory).stop(ctx)
}
func (s DarwinService) Start(ctx context.Context) error {
	return installedLaunchd(s.Directory).start(ctx)
}
func (s DarwinService) MainPID(ctx context.Context) (int, error) {
	return launchdPID(ctx, "system/"+launchdServiceLabel)
}

type Service struct{ Directory string }

func (s Service) Stop(ctx context.Context) error {
	if err := maintenance.GuardAdmission(s.Directory); err != nil {
		return err
	}
	return (DarwinService(s)).Stop(ctx)
}
func (s Service) Start(ctx context.Context) error { return (DarwinService(s)).Start(ctx) }

type installedRecoveryMaintainer struct{ directory string }

func NewRecoveryMaintainer(directory string) backupapp.RecoveryMaintainer {
	return &installedRecoveryMaintainer{directory: directory}
}

func (m *installedRecoveryMaintainer) Supported() (bool, string) {
	if os.Geteuid() != 0 {
		return false, "automatic maintenance requires the root-owned installed launchd system service"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	physical, err := filepath.EvalSymlinks(m.directory)
	if err != nil || checkLaunchdPath(physical, 0, true, false) != nil {
		return false, "installed data directory must be root-owned and not group/world writable"
	}
	s := installedLaunchd(m.directory)
	executable, err := s.executable(ctx)
	if err != nil {
		return false, "installed launchd service configuration is unavailable or differs"
	}
	if err := checkLaunchdPath(executable, 0, false, false); err != nil {
		return false, "installed launchd executable is not an owned regular file"
	}
	if err := checkSystemLaunchdTree(ctx, []string{executable, s.plist}, physical); err != nil {
		return false, "automatic maintenance requires protected root-owned deployment, executable and LaunchDaemons directories"
	}
	pid, err := launchdPID(ctx, "system/"+s.label)
	self, selfErr := os.Executable()
	a, aErr := os.Stat(executable)
	b, bErr := os.Stat(self)
	if err != nil || pid != os.Getpid() || selfErr != nil || aErr != nil || bErr != nil || !os.SameFile(a, b) {
		return false, "automatic maintenance requires this process to own the installed launchd service"
	}
	return true, ""
}

func (m *installedRecoveryMaintainer) StartRecovery(ctx context.Context, id string, timeout time.Duration) error {
	if timeout < time.Minute || timeout > 24*time.Hour {
		return errors.New("invalid recovery maintenance timeout")
	}
	lease, err := lockfile.Acquire(filepath.Join(m.directory, ".recovery-maintenance.lock"))
	if err != nil {
		return err
	}
	defer lease.Close()
	if err := maintenance.GuardAdmission(m.directory); err != nil {
		return err
	}
	return StartDarwinMaintenance(ctx, m.directory, id, timeout+2*time.Minute, "recovery-maintenance")
}
func (m *installedRecoveryMaintainer) StartRestore(ctx context.Context, id string, timeout time.Duration) error {
	if timeout < time.Minute || timeout > 24*time.Hour {
		return errors.New("invalid restore maintenance timeout")
	}
	if err := maintenance.GuardAdmission(m.directory); err != nil {
		return err
	}
	return StartDarwinMaintenance(ctx, m.directory, id, timeout+2*time.Minute, "recovery-restore")
}

type launchdTask struct {
	Version   int       `json:"version"`
	ID        string    `json:"id"`
	Action    string    `json:"action"`
	SHA256    string    `json:"sha256"`
	CreatedAt time.Time `json:"createdAt"`
	Timeout   int64     `json:"timeoutSeconds"`
	Attempted bool      `json:"attempted"`
	Done      bool      `json:"done"`
}

func recoveryAction(action string) string {
	switch action {
	case "update-protected-helper":
		return "update-protected-recover"
	case "recovery-maintenance":
		return "recovery-maintenance-restart"
	case "recovery-restore":
		return "recovery-restore-restart"
	default:
		return ""
	}
}

func taskPaths(directory, id string) (string, error) {
	v, err := uuid.Parse(id)
	if err != nil || v == (uuid.UUID{}) || v.String() != id || !filepath.IsAbs(directory) {
		return "", errors.New("invalid launchd maintenance identity")
	}
	return filepath.Join(directory, launchdTaskDirectory, id), nil
}

func syncLaunchdDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func saveLaunchdTask(directory string, task launchdTask) error {
	data, err := json.Marshal(task)
	if err != nil {
		return err
	}
	if err := atomicfile.WriteFile(filepath.Join(directory, "job.json"), data, 0600); err != nil {
		return err
	}
	return syncLaunchdDirectory(directory)
}

func readLaunchdTask(directory, id string, settings launchdSettings) (launchdTask, error) {
	var task launchdTask
	for _, path := range []string{filepath.Dir(directory), directory} {
		if err := checkLaunchdPath(path, settings.owner, true, true); err != nil {
			return task, err
		}
	}
	path := filepath.Join(directory, "job.json")
	if err := checkLaunchdPath(path, settings.owner, false, true); err != nil {
		return task, err
	}
	f, err := os.Open(path)
	if err != nil {
		return task, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) > 4096 {
		return task, errors.New("invalid launchd maintenance descriptor")
	}
	if err := json.Unmarshal(data, &task, json.RejectUnknownMembers(true)); err != nil {
		return task, err
	}
	if _, err := hex.DecodeString(task.SHA256); err != nil {
		return task, errors.New("invalid launchd helper checksum")
	}
	if task.Version != 1 || (task.Done && !task.Attempted) || task.ID != id || recoveryAction(task.Action) == "" || len(task.SHA256) != 64 || task.CreatedAt.IsZero() || task.Timeout < 60 || task.Timeout > int64(25*time.Hour/time.Second) {
		return task, errors.New("invalid launchd maintenance descriptor")
	}
	return task, nil
}

// StartDarwinMaintenance hands an admitted operation to an independent launchd
// job. The preserved helper remains executable across binary rename gaps.
func StartDarwinMaintenance(ctx context.Context, directory, id string, timeout time.Duration, action string) error {
	m := &installedRecoveryMaintainer{directory: directory}
	if ok, reason := m.Supported(); !ok {
		return errors.New(reason)
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	return launchDarwinTask(ctx, directory, id, timeout, action, executable, systemLaunchd())
}

func launchDarwinTask(ctx context.Context, directory, id string, timeout time.Duration, action, executable string, settings launchdSettings) error {
	if recoveryAction(action) == "" || timeout < time.Minute || timeout > 25*time.Hour {
		return errors.New("invalid launchd maintenance action/timeout")
	}
	directory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return err
	}
	if err := checkLaunchdPath(directory, settings.owner, true, false); err != nil {
		return err
	}
	job, err := taskPaths(directory, id)
	if err != nil {
		return err
	}
	parent := filepath.Dir(job)
	if err := os.Mkdir(parent, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := checkLaunchdPath(parent, settings.owner, true, true); err != nil {
		return err
	}
	if settings.domain == "system" {
		if err := checkSystemLaunchdTree(ctx, []string{executable}, parent, settings.plistDirectory); err != nil {
			return err
		}
	}
	if err := syncLaunchdDirectory(directory); err != nil {
		return err
	}
	pruneLaunchdTasks(ctx, parent, settings)
	if err := checkLaunchdPath(executable, settings.owner, false, false); err != nil {
		return err
	}
	if err := os.Mkdir(job, 0700); err != nil {
		return err
	}
	bootstrapping := false
	defer func() {
		if !bootstrapping {
			_ = os.RemoveAll(job)
		}
	}()
	input, err := os.Open(executable)
	if err != nil {
		return err
	}
	defer input.Close()
	before, err := input.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maxLaunchdHelperBytes {
		return errors.New("invalid launchd maintenance executable")
	}
	// Leave reserve space for the live service while preserving its executable.
	var disk syscall.Statfs_t
	if err := syscall.Statfs(job, &disk); err != nil {
		return err
	}
	needed := uint64(before.Size()) + (256 << 20)
	block := uint64(disk.Bsize)
	if block == 0 || uint64(disk.Bavail) < (needed+block-1)/block {
		return errors.New("insufficient deployment space for launchd maintenance helper and reserve")
	}
	output, err := os.OpenFile(filepath.Join(job, "helper"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		return err
	}
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(output, hash), io.LimitReader(input, maxLaunchdHelperBytes+1))
	syncErr := output.Sync()
	closeErr := output.Close()
	after, statErr := input.Stat()
	if err := errors.Join(copyErr, syncErr, closeErr, statErr); err != nil {
		return err
	}
	if n != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return errors.New("maintenance executable changed while copying")
	}
	task := launchdTask{Version: 1, ID: id, Action: action, SHA256: hex.EncodeToString(hash.Sum(nil)), CreatedAt: time.Now().UTC(), Timeout: int64(timeout / time.Second)}
	if err := saveLaunchdTask(job, task); err != nil {
		return err
	}
	if err := syncLaunchdDirectory(parent); err != nil {
		return err
	}
	label := launchdTaskPrefix + id
	properties := map[string]any{"Label": label, "ProgramArguments": []string{filepath.Join(job, "helper"), "launchd-maintenance-supervisor", directory, id}, "RunAtLoad": true, "KeepAlive": map[string]bool{"SuccessfulExit": false}, "AbandonProcessGroup": false, "ExitTimeOut": 30, "ThrottleInterval": 10, "ProcessType": "Background", "Umask": 63, "StandardOutPath": filepath.Join(job, "helper.log"), "StandardErrorPath": filepath.Join(job, "helper.log")}
	if len(settings.environment) != 0 {
		properties["EnvironmentVariables"] = settings.environment
	}
	data, err := json.Marshal(properties)
	if err != nil {
		return err
	}
	convert := exec.CommandContext(ctx, "/usr/bin/plutil", "-convert", "xml1", "-o", "-", "-")
	convert.Stdin = bytes.NewReader(data)
	plist, err := convert.Output()
	if err != nil {
		return err
	}
	path := filepath.Join(settings.plistDirectory, label+".plist")
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("launchd maintenance job already exists")
	}
	if err := atomicfile.WriteFile(path, plist, 0600); err != nil {
		return err
	}
	if err := syncLaunchdDirectory(settings.plistDirectory); err != nil {
		_ = os.Remove(path)
		return err
	}
	// A lost bootstrap response is ambiguous: preserve the job and descriptor.
	bootstrapping = true
	_, err = launchctl(ctx, "bootstrap", settings.domain, path)
	return err
}

func SuperviseDarwin(args []string) error { return superviseDarwin(args, systemLaunchd()) }

func superviseDarwin(args []string, settings launchdSettings) error {
	if len(args) != 2 || uint32(os.Geteuid()) != settings.owner {
		return errors.New("invalid launchd maintenance invocation")
	}
	job, err := taskPaths(args[0], args[1])
	if err != nil {
		return err
	}
	task, err := readLaunchdTask(job, args[1], settings)
	if err != nil {
		return err
	}
	owner, err := lockfile.Acquire(filepath.Join(job, ".supervisor.lock"))
	if err != nil {
		return err
	}
	defer owner.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	pid, err := launchdPID(ctx, settings.domain+"/"+launchdTaskPrefix+task.ID)
	cancel()
	if err != nil || pid != os.Getpid() {
		return errors.New("supervisor is not the launchd job owner")
	}
	executable := filepath.Join(job, "helper")
	if err := checkLaunchdPath(executable, settings.owner, false, false); err != nil {
		return err
	}
	if settings.domain == "system" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := checkSystemLaunchdTree(ctx, []string{executable}, settings.plistDirectory)
		cancel()
		if err != nil {
			return err
		}
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	a, err := os.Stat(self)
	if err != nil {
		return err
	}
	b, err := os.Stat(executable)
	if err != nil || !os.SameFile(a, b) {
		return errors.New("maintenance helper image differs")
	}
	f, err := os.Open(executable)
	if err != nil {
		return err
	}
	hash := sha256.New()
	_, err = io.Copy(hash, f)
	_ = f.Close()
	if err != nil || hex.EncodeToString(hash.Sum(nil)) != task.SHA256 {
		return errors.New("maintenance helper checksum differs")
	}
	run := func(action string, timeout time.Duration) error {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, executable, action, args[0], task.ID)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		return cmd.Run() // Same process group: launchd kills descendants on supervisor death.
	}
	if !task.Done {
		if !task.Attempted {
			deadline := task.CreatedAt.Add(time.Duration(task.Timeout) * time.Second)
			if time.Until(deadline) > 0 {
				// Bootstrap can schedule this job before the API releases its
				// admission lease. A failed lock attempt must not abort the job.
				handoff, cancel := context.WithDeadline(context.Background(), deadline)
				err := waitForLaunchdHandoff(handoff, args[0])
				cancel()
				if err != nil && !errors.Is(err, context.DeadlineExceeded) {
					return err
				}
			}
			task.Attempted = true
			if err := saveLaunchdTask(job, task); err != nil {
				return err
			}
			remaining := min(time.Until(deadline), time.Duration(task.Timeout)*time.Second)
			if remaining > 0 {
				if err := run(task.Action, remaining); err != nil {
					// Exit nonzero so launchd clears the entire old process group,
					// then restarts this preserved helper in recovery-only mode.
					return fmt.Errorf("maintenance worker failed; independent recovery will follow: %w", err)
				}
				task.Done = true
			}
		}
		if !task.Done {
			// A newer admitted update proves the previous journal was terminal.
			// A stale launchd job has no authority to recover that newer update.
			stale := false
			if task.Action == "update-protected-helper" {
				record, err := maintenance.Read(args[0])
				if err != nil {
					return err
				}
				stale = record != nil && record.ID != task.ID
			}
			if !stale {
				if err := run(recoveryAction(task.Action), 2*time.Minute); err != nil {
					return fmt.Errorf("maintenance recovery remains pending: %w", err)
				}
			}
		}
		task.Done = true
		if err := saveLaunchdTask(job, task); err != nil {
			return err
		}
	}
	path := filepath.Join(settings.plistDirectory, launchdTaskPrefix+task.ID+".plist")
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := syncLaunchdDirectory(settings.plistDirectory); err != nil {
		return err
	}
	// The completed descriptor/helper are retained until the next maintenance;
	// removing the running helper before bootout would create a crash window.
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = launchctl(ctx, "bootout", settings.domain+"/"+launchdTaskPrefix+task.ID)
	return err
}

func waitForLaunchdHandoff(ctx context.Context, directory string) error {
	timer := time.NewTicker(50 * time.Millisecond)
	defer timer.Stop()
	for {
		lease, err := lockfile.Acquire(filepath.Join(directory, ".recovery-maintenance.lock"))
		if err == nil {
			return lease.Close()
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// Keep one completed helper available across cleanup crashes, then retire it
// before the next job. Unknown or active descriptors are never removed.
func pruneLaunchdTasks(ctx context.Context, parent string, settings launchdSettings) {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return
	}
	for _, entry := range entries {
		path, err := taskPaths(filepath.Dir(parent), entry.Name())
		if err != nil {
			continue
		}
		task, err := readLaunchdTask(path, entry.Name(), settings)
		if err != nil || !task.Done {
			continue
		}
		target := settings.domain + "/" + launchdTaskPrefix + task.ID
		pid, err := launchdPID(ctx, target)
		if err == nil && pid > 0 {
			continue
		}
		if err != nil && !errors.Is(err, errLaunchdJobMissing) {
			continue
		}
		if err == nil {
			if _, err := launchctl(ctx, "bootout", target); err != nil {
				continue
			}
		}
		plist := filepath.Join(settings.plistDirectory, launchdTaskPrefix+task.ID+".plist")
		if err := os.Remove(plist); err != nil && !errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err := syncLaunchdDirectory(settings.plistDirectory); err != nil {
			continue
		}
		_ = os.RemoveAll(path)
	}
}
