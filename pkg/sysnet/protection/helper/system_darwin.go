package helper

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/pf"
	"golang.org/x/sys/unix"
)

// Supported reports whether this platform has the protection service.
const Supported = true

// NewConfig returns the production configuration of the service.
func NewConfig() Config {
	return Config{StateFile: StateFile, Socket: Socket, Engine: pf.NewEngine(StateDir), BootID: BootID, Group: EnsureGroup, PeerUID: PeerUID, StopSelf: selfStop}
}

// RunDaemon runs the service until ctx ends.
func RunDaemon(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("the Network Protection service must run as root")
	}
	if err := os.MkdirAll(StateDir, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(SocketDir, 0o755); err != nil {
		return err
	}
	return NewServer(NewConfig()).Run(ctx)
}

// BootID identifies the current boot session.
func BootID() string {
	id, err := unix.Sysctl("kern.bootsessionuuid")
	if err != nil {
		return ""
	}
	return id
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return pf.Exec(ctx, "", name, args...)
}

// lookupGroup returns the gid of GroupName.
func lookupGroup(ctx context.Context) (int, bool) {
	out, err := run(ctx, "/usr/bin/dscl", ".", "-read", "/Groups/"+GroupName, "PrimaryGroupID")
	if err != nil {
		return 0, false
	}
	_, value, ok := strings.Cut(strings.TrimSpace(out), ":")
	if !ok {
		return 0, false
	}
	gid, err := strconv.Atoi(strings.TrimSpace(value))
	return gid, err == nil && gid > 0
}

// EnsureGroup returns the gid of the socket group, creating it as a hidden
// system group (gid 340-399, the first one free) if it does not exist. No
// user is a member: only processes started as root can take the group.
func EnsureGroup(ctx context.Context) (int, error) {
	if gid, ok := lookupGroup(ctx); ok {
		return gid, nil
	}
	out, err := run(ctx, "/usr/bin/dscl", ".", "-list", "/Groups", "PrimaryGroupID")
	if err != nil {
		return 0, fmt.Errorf("list groups: %w", err)
	}
	used := map[int]bool{}
	for line := range strings.SplitSeq(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			if gid, err := strconv.Atoi(fields[1]); err == nil {
				used[gid] = true
			}
		}
	}
	for gid := 340; gid < 400; gid++ {
		if used[gid] {
			continue
		}
		if _, err := run(ctx, "/usr/sbin/dseditgroup", "-o", "create", "-r", "Yuhaiin Network Protection", "-i", strconv.Itoa(gid), GroupName); err != nil {
			return 0, fmt.Errorf("create group %s: %w", GroupName, err)
		}
		if got, ok := lookupGroup(ctx); ok {
			return got, nil
		}
		return 0, fmt.Errorf("group %s was not created", GroupName)
	}
	return 0, errors.New("no free group id between 340 and 399")
}

// DeleteGroup removes the socket group.
func DeleteGroup(ctx context.Context) error {
	if _, ok := lookupGroup(ctx); !ok {
		return nil
	}
	_, err := run(ctx, "/usr/sbin/dseditgroup", "-o", "delete", GroupName)
	return err
}

const plistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>` + Label + `</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>protection</string>
        <string>daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>UserName</key>
    <string>root</string>
    <key>StandardOutPath</key>
    <string>/var/log/yuhaiin-protection.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/yuhaiin-protection.log</string>
</dict>
</plist>
`

func plist(binary string) []byte {
	var escaped bytes.Buffer
	_ = xml.EscapeText(&escaped, []byte(binary))
	return fmt.Appendf(nil, plistTemplate, escaped.String())
}

// DaemonLoaded reports whether launchd has the service loaded.
func DaemonLoaded(ctx context.Context) bool {
	_, err := run(ctx, "/bin/launchctl", "print", "system/"+Label)
	return err == nil
}

// DaemonDisabled reports whether launchd keeps the service from loading at
// boot (a "launchctl disable" override).
func DaemonDisabled(ctx context.Context) bool {
	out, err := run(ctx, "/bin/launchctl", "print-disabled", "system")
	if err != nil {
		return false
	}
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, `"`+Label+`"`) {
			return strings.HasSuffix(line, "disabled") || strings.HasSuffix(line, "true")
		}
	}
	return false
}

// savedEnabled reports whether the saved state requests protection.
func savedEnabled() bool {
	s, _, err := LoadState(StateFile)
	return err == nil && s.Enabled
}

// InstallDaemon installs the service's LaunchDaemon, running binary. The
// service only runs while the kill switch is on: with protection off the job
// is installed but disabled, so no root process stays resident and nothing
// starts at boot. With protection on it is enabled, started (or, after an
// update, restarted onto binary) and starts at every boot before any user
// logs in.
func InstallDaemon(ctx context.Context, binary string) error {
	if os.Geteuid() != 0 {
		return errors.New("installing the Network Protection service requires root")
	}
	if !strings.HasPrefix(binary, "/") {
		return fmt.Errorf("service binary %q is not an absolute path", binary)
	}
	if _, err := os.Stat(binary); err != nil {
		return fmt.Errorf("service binary: %w", err)
	}
	if err := os.MkdirAll(StateDir, 0o700); err != nil {
		return err
	}
	// The group exists from installation on, so Yuhaiin joins it at
	// startup and its connections already pass when protection is enabled.
	if _, err := EnsureGroup(ctx); err != nil {
		return err
	}
	want := plist(binary)
	current, _ := os.ReadFile(PlistPath)
	changed := !bytes.Equal(current, want)
	if changed {
		if DaemonLoaded(ctx) {
			if out, err := run(ctx, "/bin/launchctl", "bootout", "system/"+Label); err != nil {
				return fmt.Errorf("stop the protection service: %w: %s", err, out)
			}
		}
		if err := pf.WriteFileAtomic(PlistPath, want, 0o644); err != nil {
			return err
		}
	}
	if !savedEnabled() {
		return DisableDaemon(ctx)
	}
	if !changed && DaemonLoaded(ctx) {
		// Reinstalling or updating: the running service may still be
		// the previous build.
		_, err := restartIfOutdated(ctx)
		return err
	}
	return StartDaemon(ctx)
}

// StartDaemon enables the service and starts it; it then also starts at
// every boot. A missing LaunchDaemon is installed from Binary.
func StartDaemon(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("starting the Network Protection service requires root")
	}
	if _, err := os.Stat(PlistPath); err != nil {
		if _, binErr := os.Stat(Binary); binErr != nil {
			return fmt.Errorf("the protection service is not installed and %s is missing; run: sudo yuhaiin install", Binary)
		}
		if _, err := EnsureGroup(ctx); err != nil {
			return err
		}
		if err := pf.WriteFileAtomic(PlistPath, plist(Binary), 0o644); err != nil {
			return err
		}
	}
	if out, err := run(ctx, "/bin/launchctl", "enable", "system/"+Label); err != nil {
		return fmt.Errorf("enable the protection service: %w: %s", err, out)
	}
	if !DaemonLoaded(ctx) {
		if out, err := run(ctx, "/bin/launchctl", "bootstrap", "system", PlistPath); err != nil {
			return fmt.Errorf("start the protection service: %w: %s", err, out)
		}
	}
	return WaitService(ctx, 15*time.Second)
}

// EnsureDaemon starts the service if it is not running.
func EnsureDaemon(ctx context.Context) error {
	if DaemonLoaded(ctx) && !DaemonDisabled(ctx) {
		return nil
	}
	return StartDaemon(ctx)
}

// DisableDaemon stops the service and keeps launchd from starting it again,
// also at boot, until StartDaemon. Rules in the kernel are not touched.
func DisableDaemon(ctx context.Context) error {
	var result error
	if out, err := run(ctx, "/bin/launchctl", "disable", "system/"+Label); err != nil {
		result = fmt.Errorf("disable the protection service: %w: %s", err, out)
	}
	if DaemonLoaded(ctx) {
		if out, err := run(ctx, "/bin/launchctl", "bootout", "system/"+Label); err != nil && DaemonLoaded(ctx) {
			result = errors.Join(result, fmt.Errorf("stop the protection service: %w: %s", err, out))
		}
	}
	return result
}

// StopDaemon is DisableDaemon (kept for callers that only want it stopped).
func StopDaemon(ctx context.Context) error { return DisableDaemon(ctx) }

// selfStop is how the running service ends itself once protection is off:
// launchd is told not to start it again, then unloads it, which stops this
// process. It runs in the background so the reply to the client goes out
// first.
func selfStop(cancelled func() bool) {
	go func() {
		time.Sleep(300 * time.Millisecond)
		if cancelled() {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		log.Info("network protection is off; stopping the protection service until it is enabled again")
		if err := DisableDaemon(ctx); err != nil {
			log.Error("network protection: stopping the service failed", "err", err)
		}
	}()
}

// UninstallDaemon stops the service and removes its LaunchDaemon and
// launchd's override for it.
func UninstallDaemon(ctx context.Context) error {
	err := DisableDaemon(ctx)
	if rmErr := os.Remove(PlistPath); rmErr != nil && !os.IsNotExist(rmErr) {
		err = errors.Join(err, rmErr)
	}
	_, _ = run(ctx, "/bin/launchctl", "enable", "system/"+Label)
	return err
}

// LookupGroupID returns the socket group's gid without the service.
func LookupGroupID(ctx context.Context) int {
	gid, _ := lookupGroup(ctx)
	return gid
}

// RestartDaemon restarts the running service so it runs the binary now on
// disk. Protection holds meanwhile: the rules stay in the kernel, and the new
// process verifies and keeps them when it starts.
func RestartDaemon(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("restarting the Network Protection service requires root")
	}
	if !DaemonLoaded(ctx) {
		if !savedEnabled() {
			return errors.New("the protection service is not running because the kill switch is off; it starts when the kill switch is enabled")
		}
		return StartDaemon(ctx)
	}
	if out, err := run(ctx, "/bin/launchctl", "kickstart", "-k", "system/"+Label); err != nil {
		return fmt.Errorf("restart the protection service: %w: %s", err, out)
	}
	return WaitService(ctx, 15*time.Second)
}

// restartIfOutdated restarts the service when it reports another build than
// this executable. It reports whether it restarted.
func restartIfOutdated(ctx context.Context) (bool, error) {
	if os.Geteuid() != 0 || !DaemonLoaded(ctx) {
		return false, nil
	}
	c := NewClient("api")
	status, err := c.Call(ctx, OpStatus, nil)
	c.Close()
	ours := BuildID()
	if err != nil || !outdated(status.ServiceVersion, ours) {
		return false, nil
	}
	log.Info("network protection: restarting the protection service to run the updated binary", "running", status.ServiceVersion, "installed", ours)
	if err := RestartDaemon(ctx); err != nil {
		return false, err
	}
	c = NewClient("api")
	defer c.Close()
	if after, err := c.Call(ctx, OpStatus, nil); err == nil && after.ServiceVersion != ours {
		// The service runs Binary; this process runs another build
		// (for example a development build elsewhere). Not an error.
		log.Warn("network protection: the protection service runs a different build than this process", "service", after.ServiceVersion, "this", ours, "binary", Binary)
	}
	return true, nil
}

var ensureCurrentOnce sync.Once

// EnsureCurrent restarts an outdated protection service once per process.
// The Yuhaiin core calls it at startup, which is what happens after an
// update replaced the binary and restarted the core.
func EnsureCurrent(ctx context.Context) {
	ensureCurrentOnce.Do(func() {
		if _, err := restartIfOutdated(ctx); err != nil {
			log.Error("network protection: restarting the updated protection service failed; the previous service keeps protecting", "err", err)
		}
	})
}
