//go:build !android

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
)

func init() {
	dialer.DefaultRoutingMark = device.Mark

	var disabledMark bool
	dialer.DefaultMarkSymbol = func(socket int32) bool {
		if disabledMark {
			return false
		}

		err := dialer.LinuxMarkSymbol(socket, device.Mark)
		if err != nil {
			if errors.Is(err, syscall.EPERM) {
				log.Info("check mark symbol no permission, disable it")
				disabledMark = true
				return false
			}

			log.Error("check mark symbol failed", "err", err)
		}

		return err == nil
	}

	if configuration.ProcessDumper {
		// try start bpf
		netlink.StartBpf()
	}
}

const systemdServiceTemplate = `[Unit]
Description=yuhaiin transparent proxy
After=network.target

[Service]
ExecStart=%s -host %s -path %s
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`

var (
	// Default paths that can be overridden for testing
	systemdServicePath = "/etc/systemd/system/yuhaiin.service"
	targetBin          = "/usr/local/bin/yuhaiin"

	// For testing purposes, we can disable actual systemd commands
	disableSystemdCommands = false
)

// execSystemdCommand executes a systemd command and returns the output and error
// If disableSystemdCommands is true, it returns nil for both output and error
func execSystemdCommand(args ...string) ([]byte, error) {
	if disableSystemdCommands {
		return nil, nil
	}
	return exec.Command("systemctl", args...).CombinedOutput()
}

// install implements the service installation for Linux using systemd
func install(args []string) error {
	flag := flag.NewFlagSet("yuhaiin", flag.ExitOnError)
	host := flag.String("host", "0.0.0.0:50051", "gRPC and http listen host")
	path := flag.String("path", "/var/lib/yuhaiin", "save data path")
	if err := flag.Parse(args); err != nil {
		return err
	}

	// Check if running as root
	if os.Getuid() != 0 {
		return fmt.Errorf("installing service requires root privileges; try running with sudo")
	}

	// Check if service is already installed and running
	serviceWasRunning := isServiceRunning()
	log.Info("checking if service was already running", "running", serviceWasRunning)

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to find our own executable path: %w", err)
	}

	same, err := sameFile(exe, targetBin)
	if err != nil {
		return err
	}

	// Do not overwrite targetBin if it's already pointing to the executable
	if !same {
		if err := copyBinary(exe, targetBin); err != nil {
			return err
		}
	}

	// Create data directory if it doesn't exist
	if err := os.MkdirAll(*path, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	// Write systemd service file
	serviceContent := fmt.Sprintf(systemdServiceTemplate, targetBin, *host, *path)
	if err := os.WriteFile(systemdServicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write systemd service file: %w", err)
	}

	// Reload systemd daemon
	if out, err := execSystemdCommand("daemon-reload"); err != nil {
		return fmt.Errorf("error reloading systemd: %v, %s", err, out)
	}

	// Enable service
	if out, err := execSystemdCommand("enable", "yuhaiin.service"); err != nil {
		return fmt.Errorf("error enabling yuhaiin service: %v, %s", err, out)
	}

	if serviceWasRunning {
		log.Info("previous service was running, restarting service to apply changes")
		if err := restart(nil); err != nil {
			return fmt.Errorf("error restarting service: %w", err)
		}
	} else {
		// Start service
		if out, err := execSystemdCommand("start", "yuhaiin.service"); err != nil {
			return fmt.Errorf("error starting yuhaiin service: %v, %s", err, out)
		}
	}
	log.Info("yuhaiin service installed and started successfully")
	return nil
}

// uninstall removes the systemd service
func uninstall(args []string) error {
	// Check if running as root
	if os.Getuid() != 0 {
		return fmt.Errorf("uninstalling service requires root privileges; try running with sudo")
	}

	// Stop service if running
	if out, err := execSystemdCommand("stop", "yuhaiin.service"); err != nil {
		log.Warn("error stopping yuhaiin service", "err", err, "out", string(out))
	}

	// Disable service
	if out, err := execSystemdCommand("disable", "yuhaiin.service"); err != nil {
		log.Warn("error disabling yuhaiin service", "err", err, "out", string(out))
	}

	// Remove service file
	if err := os.Remove(systemdServicePath); err != nil && !os.IsNotExist(err) {
		log.Warn("error removing service file", "err", err, "path", systemdServicePath)
	}

	// Reload systemd daemon
	if out, err := execSystemdCommand("daemon-reload"); err != nil {
		log.Warn("error reloading systemd", "err", err, "out", string(out))
	}

	// Do not delete targetBin if it's a symlink
	if !isSymlink(targetBin) {
		if err := os.Remove(targetBin); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("error removing binary: %w", err)
		}
	}

	log.Info("yuhaiin service uninstalled successfully")
	return nil
}

// stop stops the systemd service
func stop(args []string) error {
	// Check if running as root
	if os.Getuid() != 0 {
		return fmt.Errorf("stopping service requires root privileges; try running with sudo")
	}

	if out, err := execSystemdCommand("stop", "yuhaiin.service"); err != nil {
		return fmt.Errorf("error stopping yuhaiin service: %v, %s", err, out)
	}
	return nil
}

// start starts the systemd service
func start(args []string) error {
	// Check if running as root
	if os.Getuid() != 0 {
		return fmt.Errorf("starting service requires root privileges; try running with sudo")
	}

	if out, err := execSystemdCommand("start", "yuhaiin.service"); err != nil {
		return fmt.Errorf("error starting yuhaiin service: %v, %s", err, out)
	}
	return nil
}

// restart restarts the systemd service
func restart(args []string) error {
	// Check if running as root
	if os.Getuid() != 0 {
		return fmt.Errorf("restarting service requires root privileges; try running with sudo")
	}

	if out, err := execSystemdCommand("restart", "yuhaiin.service"); err != nil {
		return fmt.Errorf("error restarting yuhaiin service: %v, %s", err, out)
	}
	return nil
}

// Helper functions

// copyBinary copies binary file `src` into `dst`.
func copyBinary(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	tmpBin := dst + ".tmp"
	f, err := os.Create(tmpBin)
	if err != nil {
		return err
	}
	srcf, err := os.Open(src)
	if err != nil {
		f.Close()
		return err
	}
	_, err = io.Copy(f, srcf)
	srcf.Close()
	if err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpBin, 0755); err != nil {
		return err
	}
	if err := os.Rename(tmpBin, dst); err != nil {
		return err
	}

	return nil
}

func isSymlink(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && (fi.Mode()&os.ModeSymlink == os.ModeSymlink)
}

// sameFile returns true if both file paths exist and resolve to the same file.
func sameFile(path1, path2 string) (bool, error) {
	dst1, err := filepath.EvalSymlinks(path1)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("EvalSymlinks(%s): %w", path1, err)
	}
	dst2, err := filepath.EvalSymlinks(path2)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("EvalSymlinks(%s): %w", path2, err)
	}
	return dst1 == dst2, nil
}

// isServiceRunning checks if the yuhaiin systemd service is currently running
func isServiceRunning() bool {
	out, err := execSystemdCommand("is-active", "yuhaiin.service")
	if err != nil {
		return false
	}

	// Trim any whitespace and check if the service is active
	status := strings.TrimSpace(string(out))
	return status == "active"
}
