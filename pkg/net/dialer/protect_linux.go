//go:build linux && !android

package dialer

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// InstallMarkProtector probes SO_MARK once and, if the process may set it,
// installs the mark as the Socket Protection. Setting SO_MARK needs
// CAP_NET_ADMIN; without it no protector is installed and sockets fall back
// to egress binding while our TUN is up.
func InstallMarkProtector(mark uint32) error {
	method := "SO_MARK"
	if err := probeMark(mark); err != nil {
		reason := err.Error()
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			reason = "setting SO_MARK needs CAP_NET_ADMIN (run as root or grant the capability)"
		}
		SetSocketProtector(nil)
		SetProtectionUnavailable(&ProtectionUnavailable{Method: method, Mark: mark, Reason: reason})
		return fmt.Errorf("socket protection unavailable: %w", err)
	}
	SetProtectionUnavailable(nil)
	SetSocketProtector(&SocketProtector{
		Method: method,
		Mark:   mark,
		Protect: func(fd int32) error {
			return LinuxMarkSymbol(fd, int(mark))
		},
	})
	return nil
}

func probeMark(mark uint32) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
	}
	defer unix.Close(fd)
	return LinuxMarkSymbol(int32(fd), int(mark))
}
