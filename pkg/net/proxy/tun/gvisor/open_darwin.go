package tun

import (
	"fmt"
	"os"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/utils/net"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"golang.org/x/sys/unix"
	buffer "gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func open(name string, driver listener.TunEndpointDriver, mtu int) (_ stack.LinkEndpoint, err error) {
	scheme, name, err := net.GetScheme(name)
	if err != nil {
		return nil, fmt.Errorf("get scheme failed: %w", err)
	}
	name = name[2:]

	if len(name) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("interface name too long: %s", name)
	}

	var fd int
	switch scheme {
	case "fd":
		fd, err = strconv.Atoi(name)
	case "tun":
		fallthrough
	default:
		err = fmt.Errorf("invalid tun name: %s", name)
	}
	if err != nil {
		return nil, fmt.Errorf("open tun [%s,%s] failed: %w", scheme, name, err)
	}

	file := os.NewFile(uintptr(fd), strconv.Itoa(fd))
	endpoint := NewEndpoint(&darwinWriter{file}, uint32(mtu), "")
	endpoint.SetInbound(&darwinInbound{endpoint, file, mtu})
	return endpoint, nil
}

var _ writer = (*darwinWriter)(nil)

type darwinWriter struct{ file *os.File }

func (w *darwinWriter) Write(b []byte) tcpip.Error {
	_, err := w.file.Write(b)
	if err == nil {
		return nil
	}

	log.Error("write packet failed", "err", err)
	return &tcpip.ErrClosedForSend{}
}

func (w *darwinWriter) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	// for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
	// 	if err := w.WritePacket(pkt); err != nil {
	// 		return 0, err
	// 	}
	// }
	for _, pkt := range pkts.AsSlice() {
		if err := w.Write(pkt.Data().AsRange().ToSlice()); err != nil {
			return 0, err
		}
	}

	return pkts.Len(), nil
}

func (w *darwinWriter) Close() error { return nil }

var _ inbound = (*darwinInbound)(nil)

type darwinInbound struct {
	e    stack.InjectableLinkEndpoint
	file *os.File
	mtu  int
}

func (w *darwinInbound) stop() { w.file.Close() }

func (w *darwinInbound) dispatch() (bool, tcpip.Error) {
	buf := pool.GetBytes(w.mtu)
	defer pool.PutBytes(buf)

	n, err := w.file.Read(buf)
	if err != nil {
		log.Error("receive packet failed", "err", err)
		return false, &tcpip.ErrAborted{}
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(buf[:n]),
	})
	defer pkt.DecRef()

	var p tcpip.NetworkProtocolNumber

	switch header.IPVersion(buf[:n]) {
	case header.IPv4Version:
		p = header.IPv4ProtocolNumber
	case header.IPv6Version:
		p = header.IPv6ProtocolNumber
	default:
		return true, nil
	}

	w.e.InjectInbound(p, pkt)
	return true, nil
}
