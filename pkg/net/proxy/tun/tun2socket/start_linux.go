package tun2socket

import (
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/utils/net"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
)

func openDevice(name string) (io.ReadWriteCloser, error) {
	fd, err := Open(name)
	if err != nil {
		return nil, fmt.Errorf("open tun device failed: %w", err)
	}

	return os.NewFile(uintptr(fd), "/dev/tun"), nil
}

func Open(name string) (fd int, err error) {
	scheme, name, err := net.GetScheme(name)
	if err != nil {
		return 0, fmt.Errorf("get scheme failed: %w", err)
	}
	name = name[2:]

	if len(name) >= unix.IFNAMSIZ {
		return 0, fmt.Errorf("interface name too long: %s", name)
	}

	switch scheme {
	case "tun":
		fd, err = tun.Open(name)
	case "fd":
		fd, err = strconv.Atoi(name)
	default:
		err = fmt.Errorf("invalid tun name: %s", name)
	}
	if err != nil {
		return 0, fmt.Errorf("open tun [%s,%s] failed: %w", scheme, name, err)
	}

	return fd, nil
}
