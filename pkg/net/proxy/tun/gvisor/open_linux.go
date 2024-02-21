package tun

import (
	"fmt"
	"io"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var (
	offset = 0
)

func OpenWriter(sc TunScheme, mtu int) (io.ReadWriteCloser, error) {
	fd, err := Open(sc)
	if err != nil {
		return nil, fmt.Errorf("open tun device failed: %w", err)
	}

	return os.NewFile(uintptr(fd), "/dev/tun"), nil
}

func Open(sc TunScheme) (fd int, err error) {
	if len(sc.Name) >= unix.IFNAMSIZ {
		return 0, fmt.Errorf("interface name too long: %s", sc.Name)
	}

	switch sc.Scheme {
	case "tun":
		fd, err = tun.Open(sc.Name)
	case "fd":
		fd = sc.Fd
	}
	if err != nil {
		return 0, fmt.Errorf("open tun [%v] failed: %w", sc, err)
	}

	return fd, nil
}

func open(name TunScheme, driver listener.TunEndpointDriver, mtu int) (_ stack.LinkEndpoint, err error) {
	fd, err := Open(name)
	if err != nil {
		return nil, fmt.Errorf("open tun device failed: %w", err)
	}
	return openFD(fd, mtu, driver)
}

var _ writer = (*fdWriter)(nil)

type fdWriter struct {
	fd int
	*readVDispatcher
}

func newFDWriter(fd int) (*fdWriter, error) {
	readVDispatcher, err := newReadVDispatcher(fd)
	if err != nil {
		return nil, fmt.Errorf("create readv dispatcher failed: %w", err)
	}

	return &fdWriter{
		fd:              fd,
		readVDispatcher: readVDispatcher,
	}, nil
}

func (w *fdWriter) WritePacket(pkt stack.PacketBufferPtr) tcpip.Error {
	buf := pkt.ToBuffer()
	defer buf.Release()

	if err := w.Write(buf.Flatten()); err != nil {
		return err
	}
	return nil
}

func (w *fdWriter) Write(b []byte) tcpip.Error { return rawfile.NonBlockingWrite(w.fd, b) }

func (w *fdWriter) Close() error {
	w.readVDispatcher.stop()
	return unix.Close(w.fd)
}
