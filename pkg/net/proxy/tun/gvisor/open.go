package tun

import (
	"fmt"
	"io"

	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var openFD func(fd, mtu int) (stack.LinkEndpoint, error)

func Open(sc netlink.TunScheme, driver listener.TunEndpointDriver, mtu int) (_ stack.LinkEndpoint, err error) {
	if sc.Scheme == "fd" && driver == listener.Tun_fdbased && openFD != nil {
		return openFD(sc.Fd, mtu)
	}

	w, err := OpenWriter(sc, mtu)
	if err != nil {
		return nil, fmt.Errorf("open tun failed: %w", err)
	}
	return NewEndpoint(w, uint32(mtu)), nil
}

type hiddenCloser struct {
	io.ReadWriteCloser
}

func newHiddenCloser(rwc io.ReadWriteCloser) io.ReadWriteCloser {
	return &hiddenCloser{rwc}
}

func (h *hiddenCloser) Close() error { return nil }
