//go:build linux || darwin

package servicehost

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const darwinSystemPlist = "/Library/LaunchDaemons/com.asutorufa.yuhaiin.plist"

func BootoutDarwin() error {
	if out, err := exec.Command("launchctl", "bootout", "system", darwinSystemPlist).CombinedOutput(); err != nil {
		return fmt.Errorf("bootout service: %w, %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func BootstrapDarwin() error {
	if out, err := exec.Command("launchctl", "bootstrap", "system", darwinSystemPlist).CombinedOutput(); err != nil {
		return fmt.Errorf("bootstrap service: %w, %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func KickstartDarwin(service string) (int, error) {
	out, err := exec.Command("launchctl", "kickstart", "-kp", "system/"+service).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("kickstart service: %w, %s", err, strings.TrimSpace(string(out)))
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("kickstart service returned invalid pid %q", strings.TrimSpace(string(out)))
	}
	return pid, nil
}

func EnsureDarwinKeepAlive() error {
	data, err := os.ReadFile(darwinSystemPlist)
	if err != nil {
		return err
	}
	if strings.Contains(string(data), "<key>KeepAlive</key>") {
		return nil
	}
	const keepAlive = "    <key>KeepAlive</key>\n    <true/>\n\n"
	updated := strings.Replace(string(data), "</dict>", keepAlive+"</dict>", 1)
	if updated == string(data) {
		return errors.New("launchd plist does not contain a dictionary")
	}
	tmp := darwinSystemPlist + ".update"
	_ = os.Remove(tmp)
	if err := os.WriteFile(tmp, []byte(updated), 0700); err != nil {
		return err
	}
	if err := os.Rename(tmp, darwinSystemPlist); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func WaitDarwinExit(pid int) error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		if err != nil && !errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("check stopped service process %d: %w", pid, err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for service process %d to stop", pid)
		}
		time.Sleep(250 * time.Millisecond)
	}
}
