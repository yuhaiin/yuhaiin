// modified from https://github.com/tailscale/tailscale/blob/main/cmd/tailscaled/install_darwin.go
package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
)

const darwinLaunchdPlist = `
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.asutorufa.yuhaiin</string>
    
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/yuhaiin</string>
		<string>-host</string>
		<string>%s</string>
		<string>-path</string>
		<string>%s</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>UserName</key>
    <string>root</string>

    <key>StandardOutPath</key>
    <string>/var/log/yuhaiin.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/yuhaiin.log</string>

</dict>
</plist>
`

const sysPlist = "/Library/LaunchDaemons/com.asutorufa.yuhaiin.plist"
const targetBin = "/usr/local/bin/yuhaiin"
const service = "com.asutorufa.yuhaiin"

func install(args []string) error {
	return installSystemDaemonDarwin(args)
}

func uninstall(args []string) error {
	return uninstallSystemDaemonDarwin(args)
}

func restart(args []string) error {
	if err := stop(args); err != nil {
		return err
	}

	startTime := time.Now()
	for {
		out, err := exec.Command("launchctl", "list", service).CombinedOutput()
		if err != nil {
			return fmt.Errorf("error running launchctl list %s: %v, %s", service, err, out)
		}

		pid := getPid(out)
		if pid == -1 {
			break
		}

		if time.Since(startTime) > time.Minute {
			log.Error("timeout waiting for service to stop, please check manually")
		} else {
			log.Info("check service is running, wait for 1 second", "pid", pid)
			time.Sleep(time.Second)
		}
	}

	return start(args)
}

func stop(args []string) error {
	if out, err := exec.Command("launchctl", "stop", service).CombinedOutput(); err != nil {
		return fmt.Errorf("error running launchctl stop %s: %v, %s", service, err, out)
	}
	return nil
}

func start(args []string) error {
	if out, err := exec.Command("launchctl", "start", service).CombinedOutput(); err != nil {
		return fmt.Errorf("error running launchctl start %s: %v, %s", service, err, out)
	}
	return nil
}

func uninstallSystemDaemonDarwin(args []string) (ret error) {
	if len(args) > 0 {
		return errors.New("uninstall subcommand takes no arguments")
	}

	plist, err := exec.Command("launchctl", "list", service).Output()
	_ = plist // parse it? https://github.com/DHowett/go-plist if we need something.
	running := err == nil

	if running {
		out, err := exec.Command("launchctl", "stop", service).CombinedOutput()
		if err != nil {
			fmt.Printf("launchctl stop %s: %v, %s\n", service, err, out)
			ret = err
		}
		out, err = exec.Command("launchctl", "unload", sysPlist).CombinedOutput()
		if err != nil {
			fmt.Printf("launchctl unload %s: %v, %s\n", sysPlist, err, out)
			if ret == nil {
				ret = err
			}
		}
	}

	if err := os.Remove(sysPlist); err != nil {
		if os.IsNotExist(err) {
			err = nil
		}
		if ret == nil {
			ret = err
		}
	}

	// Do not delete targetBin if it's a symlink, which happens if it was installed via
	// Homebrew.
	if isSymlink(targetBin) {
		return ret
	}

	if err := os.Remove(targetBin); err != nil {
		if os.IsNotExist(err) {
			err = nil
		}
		if ret == nil {
			ret = err
		}
	}
	return ret
}

func installSystemDaemonDarwin(args []string) (err error) {
	flag := flag.NewFlagSet("yuhaiin", flag.ExitOnError)
	host := flag.String("host", "0.0.0.0:50051", "gRPC and http listen host")
	path := flag.String("path", "/Library/Application Support/yuhaiin", "save data path")
	if err := flag.Parse(args); err != nil {
		return err
	}

	defer func() {
		if err != nil && os.Getuid() != 0 {
			err = fmt.Errorf("%w; try running yuhaiin with sudo", err)
		}
	}()

	// Best effort:
	if err := uninstallSystemDaemonDarwin(nil); err != nil {
		log.Warn("uninstall system daemon", "err", err)
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to find our own executable path: %w", err)
	}

	if out, err := exec.Command("xattr", "-rd", "com.apple.quarantine", exe).CombinedOutput(); err != nil {
		log.Warn("remove com.apple.quarantine failed: %w, output: %s", err, out)
	}

	if out, _ := exec.Command("codesign", "-v", exe).CombinedOutput(); bytes.Contains(out, []byte("code object is not signed")) {
		if out, err := exec.Command("codesign", "-s", "-", exe).CombinedOutput(); err != nil {
			log.Warn("sign with ad-hoc failed: %w, output: %s", err, out)
		}
	}

	same, err := sameFile(exe, targetBin)
	if err != nil {
		return err
	}

	// Do not overwrite targetBin with the binary file if it it's already
	// pointing to it. This is primarily to handle Homebrew that writes
	// /usr/local/bin/yuhaiin is a symlink to the actual binary.
	if !same {
		if err := copyBinary(exe, targetBin); err != nil {
			return err
		}
	}
	if err := os.WriteFile(sysPlist, fmt.Appendf(nil, darwinLaunchdPlist, *host, *path), 0700); err != nil {
		return err
	}

	if out, err := exec.Command("launchctl", "load", sysPlist).CombinedOutput(); err != nil {
		return fmt.Errorf("error running launchctl load %s: %v, %s", sysPlist, err, out)
	}

	if out, err := exec.Command("launchctl", "start", service).CombinedOutput(); err != nil {
		return fmt.Errorf("error running launchctl start %s: %v, %s", service, err, out)
	}

	return nil
}

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
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("EvalSymlinks(%s): %w", path1, err)
	}
	dst2, err := filepath.EvalSymlinks(path2)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("EvalSymlinks(%s): %w", path2, err)
	}
	return dst1 == dst2, nil
}

func getPid(data []byte) int {
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		text := scanner.Text()
		text = strings.TrimSpace(text)
		text = strings.TrimSuffix(text, ";")
		fields := strings.Split(text, "=")
		if len(fields) != 2 {
			continue
		}
		key := strings.TrimSpace(fields[0])
		key = strings.TrimPrefix(key, "\"")
		key = strings.TrimSuffix(key, "\"")
		value := strings.TrimSpace(fields[1])
		value = strings.TrimPrefix(value, "\"")
		value = strings.TrimSuffix(value, "\"")

		if strings.ToLower(key) == "pid" {
			pid, err := strconv.Atoi(value)
			if err != nil {
				continue
			}
			return pid
		}
	}

	return -1
}
