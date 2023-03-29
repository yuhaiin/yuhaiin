//go:build !windows && !darwin
// +build !windows,!darwin

package tun

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/tun2socket"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func open(name string, driver listener.TunEndpointDriver, mtu int) (_ stack.LinkEndpoint, err error) {
	fd, err := tun2socket.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open tun device failed: %w", err)
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
