package gvisor

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"testing"
	"weak"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type savedReplyHandler struct {
	netapi.Handler
	reply netapi.WriteBackFunc
}

func (h *savedReplyHandler) HandlePacket(p *netapi.Packet) {
	h.reply = p.WriteBack
	p.DecRef()
}

// Keep exactly the callback that NAT retains, with no reference to the owner
// from the test itself. A closed server must be collectible before NAT expires.
func closedUDPReply(t *testing.T) (netapi.WriteBackFunc, func() bool) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	fd := int(r.Fd())
	if err := unix.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	h := new(savedReplyHandler)
	s, err := New(&device.Opt{
		Tun:     device.TunConfig{MTU: 1500, Driver: device.DriverChannel},
		Options: &netlink.Options{Interface: netlink.TunScheme{Scheme: "fd", Fd: fd}, Inet4Address: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}},
		Handler: h,
	})
	if err != nil {
		t.Fatal(err)
	}
	// This fd-backed test has no system routes or nftables rules to remove.
	s.postDown = nil
	ref := weak.Make(s)
	p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte("request"))})
	s.HandleUDP(stack.TransportEndpointID{RemoteAddress: tcpip.AddrFrom4([4]byte{192, 0, 2, 2}), RemotePort: 12345, LocalAddress: tcpip.AddrFrom4([4]byte{198, 51, 100, 1}), LocalPort: 443}, p)
	p.DecRef()
	var closers sync.WaitGroup
	for range 4 {
		closers.Go(func() { _ = s.Close() })
	}
	closers.Wait()
	return h.reply, func() bool { return ref.Value() != nil }
}

func TestUDPReplyDoesNotRetainClosedServer(t *testing.T) {
	reply, alive := closedUDPReply(t)
	for range 2 {
		runtime.GC()
	}
	if alive() {
		t.Error("saved UDP callback retains the closed TUN server")
	}
	for range 2 {
		if _, err := reply([]byte("late reply"), &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 443}); !errors.Is(err, net.ErrClosed) {
			t.Errorf("late reply = %v, want net.ErrClosed", err)
		}
	}
	runtime.KeepAlive(reply)
}
