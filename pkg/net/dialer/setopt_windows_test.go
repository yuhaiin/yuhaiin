//go:build windows

package dialer

import (
	"context"
	"encoding/binary"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

// IP_UNICAST_IF takes the index in network byte order, IPV6_UNICAST_IF in
// host order; a dual-stack socket gets both.
func TestBindInterfaceByteOrder(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var iface *net.Interface
	for i := range ifaces {
		if ifaces[i].Flags&net.FlagUp != 0 && ifaces[i].Flags&net.FlagLoopback == 0 {
			iface = &ifaces[i]
			break
		}
	}
	if iface == nil {
		t.Skip("no non-loopback interface")
	}
	for _, network := range []string{"udp4", "udp6", "udp"} {
		opts := &Options{InterfaceName: iface.Name}
		lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
			var bindErr error
			_ = c.Control(func(fd uintptr) { bindErr = BindInterface(network, fd, opts.InterfaceName) })
			return bindErr
		}}
		pc, err := lc.ListenPacket(context.Background(), network, ":0")
		if err != nil {
			t.Fatalf("%s: %v", network, err)
		}
		raw, _ := pc.(*net.UDPConn).SyscallConn()
		_ = raw.Control(func(fd uintptr) {
			if network != "udp6" {
				v4, err := windows.GetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, IP_UNICAST_IF)
				var want [4]byte
				binary.BigEndian.PutUint32(want[:], uint32(iface.Index))
				if err != nil || uint32(v4) != binary.NativeEndian.Uint32(want[:]) {
					t.Errorf("%s IP_UNICAST_IF = %#x %v, want index %d in network order", network, v4, err, iface.Index)
				}
			}
			if network != "udp4" {
				v6, err := windows.GetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, IPV6_UNICAST_IF)
				if err != nil || v6 != iface.Index {
					t.Errorf("%s IPV6_UNICAST_IF = %d %v, want %d", network, v6, err, iface.Index)
				}
			}
		})
		_ = pc.Close()
	}
}
