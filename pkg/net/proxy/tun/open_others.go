//go:build !windows
// +build !windows

package tun

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func open(name string, driver config.TunEndpointDriver, mtu int) (_ stack.LinkEndpoint, err error) {
	if len(name) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("interface name too long: %s", name)
	}

	var fd int
	if strings.HasPrefix(name, "tun://") {
		fd, err = tun.Open(name[6:])
	} else if strings.HasPrefix(name, "fd://") {
		fd, err = strconv.Atoi(name[5:])
	} else {
		err = fmt.Errorf("invalid tun name: %s", name)
	}
	if err != nil {
		return nil, fmt.Errorf("open tun failed: %w", err)
	}

	switch driver {
	case config.Tun_channel:
		ce := NewEndpoint(newFDWriter(fd), uint32(mtu), "")
		r, err := newReadVDispatcher(fd, ce)
		if err != nil {
			return nil, fmt.Errorf("create readv dispatcher failed: %w", err)
		}
		ce.SetInbound(r)
		return ce, nil
	default:
		return fdbased.New(&fdbased.Options{
			FDs:            []int{fd},
			MTU:            uint32(mtu),
			EthernetHeader: false,
		})
	}
}

var _ writer = (*fdWriter)(nil)

type fdWriter struct{ fd int }

func newFDWriter(fd int) *fdWriter { return &fdWriter{fd: fd} }

func (w *fdWriter) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	iovecs := make([]unix.Iovec, 0, 47)
	for _, pkt := range pkts.AsSlice() {
		/*
			    old method
				sendBuffer := utils.GetBuffer()
				defer utils.PutBuffer(sendBuffer)
				sendBuffer.Reset()
				sendBuffer.Write(pkt.NetworkHeader().View())
				sendBuffer.Write(pkt.TransportHeader().View())
				sendBuffer.Write(pkt.Data().AsRange().ToOwnedView())
		*/

		for _, s := range pkt.Slices() {
			iovecs = append(iovecs, rawfile.IovecFromBytes(s))
		}
	}

	if err := rawfile.NonBlockingWriteIovec(w.fd, iovecs); err != nil {
		return 0, err
	}
	return pkts.Len(), nil
}

func (w *fdWriter) Write(b []byte) tcpip.Error { return rawfile.NonBlockingWrite(w.fd, b) }

// func (w *fdWriter) WritePacket(pkt *stack.PacketBuffer) tcpip.Error {
// 	views := pkt.Views()
// 	iovecs := make([]unix.Iovec, 0, len(views))
// 	for _, v := range views {
// 		iovecs = append(iovecs, rawfile.IovecFromBytes(v))
// 	}

// 	if err := rawfile.NonBlockingWriteIovec(w.fd, iovecs); err != nil {
// 		return err
// 	}

// 	return nil
// }
// func (w *fdWriter) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
// 	iovecs := make([]unix.Iovec, 0, 47)
// 	for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
// 		for _, s := range pkt.Views() {
// 			iovecs = append(iovecs, rawfile.IovecFromBytes(s))
// 		}
// 	}
// 	if err := rawfile.NonBlockingWriteIovec(w.fd, iovecs); err != nil {
// 		return 0, err
// 	}
// 	return pkts.Len(), nil
// }
