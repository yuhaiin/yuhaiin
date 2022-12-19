//go:build !windows
// +build !windows

package tun

import (
	"fmt"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/utils"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func open(name string, driver listener.TunEndpointDriver, mtu int) (_ stack.LinkEndpoint, err error) {
	scheme, name, err := utils.GetScheme(name)
	if err != nil {
		return nil, fmt.Errorf("get scheme failed: %w", err)
	}
	name = name[2:]

	if len(name) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("interface name too long: %s", name)
	}

	var fd int
	switch scheme {
	case "tun":
		fd, err = tun.Open(name)
	case "fd":
		fd, err = strconv.Atoi(name)
	default:
		err = fmt.Errorf("invalid tun name: %s", name)
	}
	if err != nil {
		return nil, fmt.Errorf("open tun [%s,%s] failed: %w", scheme, name, err)
	}

	return openFD(fd, mtu, driver)
}

var _ writer = (*fdWriter)(nil)

type fdWriter struct{ fd int }

func newFDWriter(fd int) *fdWriter { return &fdWriter{fd: fd} }

func (w *fdWriter) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	iovecs := make([]unix.Iovec, 0, 47)
	for _, pkt := range pkts.AsSlice() {
		/*
			    old method
				sendBuffer := pool.GetBuffer()
				defer pool.PutBuffer(sendBuffer)
				sendBuffer.Reset()
				sendBuffer.Write(pkt.NetworkHeader().View())
				sendBuffer.Write(pkt.TransportHeader().View())
				sendBuffer.Write(pkt.Data().AsRange().ToOwnedView())
		*/

		for _, s := range pkt.AsSlices() {
			iovecs = append(iovecs, rawfile.IovecFromBytes(s))
		}
	}

	if err := rawfile.NonBlockingWriteIovec(w.fd, iovecs); err != nil {
		return 0, err
	}
	return pkts.Len(), nil
}

func (w *fdWriter) Write(b []byte) tcpip.Error { return rawfile.NonBlockingWrite(w.fd, b) }
func (w *fdWriter) Close() error               { return unix.Close(w.fd) }
