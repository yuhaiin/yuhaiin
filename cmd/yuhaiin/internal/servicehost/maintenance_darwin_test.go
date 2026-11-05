//go:build darwin

package servicehost

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"uuid"

	"filippo.io/age"
	"github.com/Asutorufa/yuhaiin/pkg/app/backup/recovery"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	backuparchive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

// Only the test executable contains these child actions; production helpers have
// no environment-variable switches for bypassing installed-service admission.
func init() {
	root := os.Getenv("YUHAIIN_LAUNCHD_FIXTURE")
	if root == "" || len(os.Args) < 2 {
		return
	}
	settings := launchdSettings{domain: os.Getenv("YUHAIIN_LAUNCHD_DOMAIN"), plistDirectory: filepath.Join(root, "plists"), owner: uint32(os.Geteuid())}
	var err error
	switch os.Args[1] {
	case "launchd-maintenance-supervisor":
		err = superviseDarwin(os.Args[2:], settings)
	case "recovery-maintenance":
		directory := os.Args[2]
		if captureFixture(directory) {
			err = recovery.Capture(context.Background(), directory, os.Args[3], captureFixtureService(settings, directory))
			break
		}
		f, e := os.OpenFile(filepath.Join(directory, "attempts"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if e != nil {
			err = e
			break
		}
		_, err = f.WriteString("worker\n")
		f.Close()
		if err != nil {
			break
		}
		err = os.WriteFile(filepath.Join(directory, "worker.pid"), []byte(strconv.Itoa(os.Getpid())), 0600)
		if err != nil {
			break
		}
		scenario, _ := os.ReadFile(filepath.Join(directory, "scenario"))
		switch string(scenario) {
		case "crash":
			os.Exit(42)
		case "block":
			child := exec.Command(os.Args[0], "launchd-test-grandchild", directory)
			child.Stdout, child.Stderr = os.Stdout, os.Stderr
			if err = child.Start(); err != nil {
				break
			}
			for {
				time.Sleep(time.Hour)
			}
		}
	case "recovery-maintenance-restart":
		if captureFixture(os.Args[2]) {
			err = recovery.RestartService(context.Background(), os.Args[2], os.Args[3], captureFixtureService(settings, os.Args[2]))
			break
		}
		err = os.WriteFile(filepath.Join(os.Args[2], "recovered"), []byte("ok"), 0600)
	case "launchd-test-grandchild":
		if err = os.WriteFile(filepath.Join(os.Args[2], "grandchild.pid"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			break
		}
		for {
			time.Sleep(time.Hour)
		}
	case "launchd-test-service":
		if captureFixture(os.Args[3]) {
			directory := os.Args[3]
			lease, e := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
			if e != nil {
				err = e
				break
			}
			db, e := sqlite.Open(context.Background(), filepath.Join(directory, "state.db"))
			if e != nil {
				lease.Close()
				err = e
				break
			}
			// Keep the real SQLite and lifecycle owners live until launchd stops us.
			for {
				time.Sleep(time.Hour)
				runtime.KeepAlive(db)
				runtime.KeepAlive(lease)
			}
		}
		for {
			time.Sleep(time.Hour)
		}
	default:
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func captureFixture(directory string) bool {
	_, err := os.Stat(filepath.Join(directory, "capture-fixture"))
	return err == nil
}

type launchdCaptureService struct{ launchdService }

func (s launchdCaptureService) Stop(ctx context.Context) error  { return s.stop(ctx) }
func (s launchdCaptureService) Start(ctx context.Context) error { return s.start(ctx) }

func captureFixtureService(settings launchdSettings, directory string) launchdCaptureService {
	return launchdCaptureService{launchdService{
		settings:  settings,
		label:     launchdServiceLabel + ".fixture." + filepath.Base(filepath.Dir(directory)),
		plist:     filepath.Join(settings.plistDirectory, "capture-service.plist"),
		directory: directory,
	}}
}

type launchdFixture struct {
	root, data, executable string
	settings               launchdSettings
}

func newLaunchdFixture(t *testing.T) launchdFixture {
	t.Helper()
	var root, domain string
	if os.Getenv("YUHAIIN_TEST_SYSTEM_LAUNCHD") == "1" {
		if os.Geteuid() != 0 {
			t.Fatal("system launchd fixture requires root")
		}
		var err error
		root, err = os.MkdirTemp("/private/var/root", "yuhaiin-launchd-test-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(root) })
		domain = "system"
	} else {
		var err error
		root, err = filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		domain = "gui/" + strconv.Itoa(os.Geteuid())
		if _, err := launchctl(t.Context(), "print", domain); err != nil {
			domain = "user/" + strconv.Itoa(os.Geteuid())
			if _, err := launchctl(t.Context(), "print", domain); err != nil {
				t.Skip("no isolated user launchd domain available")
			}
		}
	}
	f := launchdFixture{root: root, data: filepath.Join(root, "data with spaces & symbols"), executable: filepath.Join(root, "source-helper")}
	for _, dir := range []string{f.data, filepath.Join(root, "plists")} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.OpenFile(f.executable, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(output, input)
	closeErr := output.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	f.settings = launchdSettings{domain: domain, plistDirectory: filepath.Join(root, "plists"), owner: uint32(os.Geteuid()), environment: map[string]string{"YUHAIIN_LAUNCHD_FIXTURE": root, "YUHAIIN_LAUNCHD_DOMAIN": domain}}
	return f
}
func waitLaunchd(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(50 * time.Second)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("timed out waiting for isolated launchd fixture")
}
func (f launchdFixture) launch(t *testing.T, id string) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = launchctl(ctx, "bootout", f.settings.domain+"/"+launchdTaskPrefix+id)
	})
	if err := launchDarwinTask(t.Context(), f.data, id, time.Minute, "recovery-maintenance", f.executable, f.settings); err != nil {
		t.Fatal(err)
	}
}
func filePID(path string) int {
	b, _ := os.ReadFile(path)
	pid, _ := strconv.Atoi(string(b))
	return pid
}

func TestLaunchdMaintenanceSurvivesWorkerAndSupervisorFailure(t *testing.T) {
	for _, scenario := range []string{"success", "crash", "supervisor_kill"} {
		t.Run(scenario, func(t *testing.T) {
			f := newLaunchdFixture(t)
			id := uuid.New().String()
			workerScenario := scenario
			if scenario == "supervisor_kill" {
				workerScenario = "block"
			}
			if err := os.WriteFile(filepath.Join(f.data, "scenario"), []byte(workerScenario), 0600); err != nil {
				t.Fatal(err)
			}
			f.launch(t, id)
			job, _ := taskPaths(f.data, id)
			if scenario == "supervisor_kill" {
				waitLaunchd(t, func() bool { return filePID(filepath.Join(f.data, "grandchild.pid")) > 0 })
				child := filePID(filepath.Join(f.data, "worker.pid"))
				grandchild := filePID(filepath.Join(f.data, "grandchild.pid"))
				// Simulate the installed executable being absent in the rename window.
				if err := os.Remove(f.executable); err != nil {
					t.Fatal(err)
				}
				pid, err := launchdPID(t.Context(), f.settings.domain+"/"+launchdTaskPrefix+id)
				if err != nil || pid < 1 {
					t.Fatal(pid, err)
				}
				if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
					t.Fatal(err)
				}
				waitLaunchd(t, func() bool {
					return syscall.Kill(child, 0) == syscall.ESRCH && syscall.Kill(grandchild, 0) == syscall.ESRCH
				})
			}
			waitLaunchd(t, func() bool { task, err := readLaunchdTask(job, id, f.settings); return err == nil && task.Done })
			waitLaunchd(t, func() bool {
				_, err := launchdPID(t.Context(), f.settings.domain+"/"+launchdTaskPrefix+id)
				return err != nil
			})
			attempts, err := os.ReadFile(filepath.Join(f.data, "attempts"))
			if err != nil || string(attempts) != "worker\n" {
				t.Fatalf("worker replayed: %q %v", attempts, err)
			}
			if scenario != "success" {
				if data, err := os.ReadFile(filepath.Join(f.data, "recovered")); err != nil || string(data) != "ok" {
					t.Fatal("independent recovery did not complete", err)
				}
			}
			if _, err := os.Stat(filepath.Join(f.settings.plistDirectory, launchdTaskPrefix+id+".plist")); !os.IsNotExist(err) {
				t.Fatal("completed job kept its boot plist", err)
			}
			pruneLaunchdTasks(t.Context(), filepath.Dir(job), f.settings)
			if _, err := os.Stat(job); !os.IsNotExist(err) {
				t.Fatal("completed helper was not retired", err)
			}
		})
	}
}

func (f launchdFixture) installService(t *testing.T, s launchdService) {
	t.Helper()
	properties := map[string]any{"Label": s.label, "ProgramArguments": []string{f.executable, "launchd-test-service", "-path", f.data}, "RunAtLoad": true, "KeepAlive": true, "EnvironmentVariables": f.settings.environment}
	raw, _ := json.Marshal(properties)
	convert := exec.CommandContext(t.Context(), "/usr/bin/plutil", "-convert", "xml1", "-o", "-", "-")
	convert.Stdin = bytes.NewReader(raw)
	xml, err := convert.Output()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.plist, xml, 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = launchctl(ctx, "bootout", f.settings.domain+"/"+s.label)
	})
}

func TestLaunchdInstalledServiceStopStartAndConfiguration(t *testing.T) {
	f := newLaunchdFixture(t)
	label := "com.asutorufa.yuhaiin.fixture." + uuid.New().String()
	path := filepath.Join(f.settings.plistDirectory, label+".plist")
	s := launchdService{settings: f.settings, label: label, plist: path, directory: f.data}
	f.installService(t, s)
	if _, err := s.executable(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.start(t.Context()); err != nil {
		t.Fatal(err)
	}
	var pid int
	waitLaunchd(t, func() bool { pid, _ = launchdPID(t.Context(), f.settings.domain+"/"+label); return pid > 0 })
	if err := s.start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if after, _ := launchdPID(t.Context(), f.settings.domain+"/"+label); after != pid {
		t.Fatal("idempotent start restarted a live service")
	}
	if err := s.stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.stop(t.Context()); err != nil {
		t.Fatal("stopping an unloaded service was not idempotent", err)
	}
	if syscall.Kill(pid, 0) != syscall.ESRCH {
		t.Fatal("stop did not wait for process exit")
	}
	s.directory = t.TempDir()
	if _, err := s.executable(t.Context()); err == nil {
		t.Fatal("different deployment directory admitted")
	}
}

func TestLaunchdDescriptorAndUnprivilegedAdmission(t *testing.T) {
	f := newLaunchdFixture(t)
	if err := launchDarwinTask(t.Context(), f.data, "../escape", time.Minute, "recovery-maintenance", f.executable, f.settings); err == nil {
		t.Fatal("invalid job identity admitted")
	}
	if err := launchDarwinTask(t.Context(), f.data, uuid.New().String(), time.Minute, "run", f.executable, f.settings); err == nil {
		t.Fatal("arbitrary worker action admitted")
	}
	if os.Geteuid() != 0 {
		if ok, reason := NewRecoveryMaintainer(f.data).Supported(); ok || !strings.Contains(reason, "root-owned") {
			t.Fatal("uninstalled user process admitted", reason)
		}
	}
}

func TestLaunchdHandoffWaitsForAdmissionLease(t *testing.T) {
	directory := t.TempDir()
	lease, err := lockfile.Acquire(filepath.Join(directory, ".recovery-maintenance.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	if err := waitForLaunchdHandoff(ctx, directory); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("handoff ignored the admission lease: %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := waitForLaunchdHandoff(t.Context(), directory); err != nil {
		t.Fatal(err)
	}
}

func TestLaunchdManagedCaptureRestartsService(t *testing.T) {
	f := newLaunchdFixture(t)
	if err := os.WriteFile(filepath.Join(f.data, "capture-fixture"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.data, "state.db")
	db, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := backupstore.New(db.DB())
	if err := store.RecordRecoveryRuntime(ctx, contractrecovery.Runtime{ManagementTLS: "disabled", WorkingDirectory: f.data}); err != nil {
		t.Fatal(err)
	}
	id := uuid.New().String()
	job := backupstore.RecoveryJob{
		ID: id, State: "queued", Target: "local", CreatedAt: time.Now().UTC(),
		Policy: contractrecovery.Policy{Recipient: key.Recipient().String(), Target: "local", AllowMaintenance: true},
	}
	if err := store.EnqueueRecovery(ctx, job); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	service := captureFixtureService(f.settings, f.data)
	f.installService(t, service.launchdService)
	if err := service.Start(ctx); err != nil {
		t.Fatal(err)
	}
	target := f.settings.domain + "/" + service.label
	oldPID, err := launchdPID(ctx, target)
	if err != nil || oldPID <= 0 {
		t.Fatal(oldPID, err)
	}
	// Confirm the service acquired its lifecycle lock before starting capture.
	waitLaunchd(t, func() bool {
		lock, err := lockfile.Acquire(filepath.Join(f.data, ".configuration.lock"))
		if lock != nil {
			_ = lock.Close()
		}
		return errors.Is(err, syscall.EWOULDBLOCK)
	})
	f.launch(t, id)
	jobDirectory, _ := taskPaths(f.data, id)
	waitLaunchd(t, func() bool {
		task, err := readLaunchdTask(jobDirectory, id, f.settings)
		return err == nil && task.Done
	})
	pid, err := launchdPID(ctx, target)
	if err != nil || pid <= 0 || pid == oldPID {
		t.Fatal("service did not restart", oldPID, pid, err)
	}
	input, err := os.Open(filepath.Join(f.data, ".recovery-archives", id+".yhb"))
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	prepared, err := backuparchive.Prepare(ctx, input, t.TempDir(), backuparchive.Decryption{Identity: key.String()})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	if !prepared.Manifest.CompleteInventory {
		t.Fatal("managed backup lacked deployment inventory")
	}
}
