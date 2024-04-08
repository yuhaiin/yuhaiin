//go:build unix && !linux

package tun

import (
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"golang.org/x/sys/unix"
	wun "golang.zx2c4.com/wireguard/tun"
)

const (
	offset = 4
)

func OpenWriter(sc netlink.TunScheme, mtu int) (netlink.Writer, error) {
	if len(sc.Name) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("interface name too long: %s", sc.Name)
	}

	var iwc netlink.Writer
	switch sc.Scheme {
	case "fd":
		iwc = newHiddenCloser(os.NewFile(uintptr(sc.Fd), strconv.Itoa(sc.Fd)))
	case "tun":
		device, err := wun.CreateTUN(sc.Name, mtu)
		if err != nil {
			return nil, fmt.Errorf("create tun failed: %w", err)
		}
		iwc = newWgReadWriteCloser(device)
	}

	return iwc, nil
}

type hiddenCloser struct {
	io.ReadWriteCloser
}

func newHiddenCloser(rwc io.ReadWriteCloser) netlink.Writer {
	return &hiddenCloser{rwc}
}

func (h *hiddenCloser) BatchSize() int { return 1 }

func (h *hiddenCloser) Write(bufs [][]byte) (int, error) {
	for i := range bufs {
		_, err := h.ReadWriteCloser.Write(bufs[i])
		if err != nil {
			return 0, err
		}
	}

	return len(bufs), nil
}
func (h *hiddenCloser) Read(bufs [][]byte, sizes []int) (n int, err error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	n, err = h.ReadWriteCloser.Read(bufs[0])
	if err != nil {
		return 0, err
	}

	sizes[0] = n

	return
}
func (h *hiddenCloser) Close() error { return nil }
