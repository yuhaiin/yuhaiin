package dialer

import (
	"context"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Wildcard UDP sockets (magicsock, STUN probes) must carry the selected
// interface; otherwise their packets follow the default route into the TUN
// and the router rejects them as a loopback cycle.
func TestSetSocketOptionsBindsWildcardUDP(t *testing.T) {
	lo, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skip("lo0 unavailable:", err)
	}

	for _, tc := range []struct {
		network, address string
		level, option    int
	}{
		{"udp4", "0.0.0.0:0", syscall.IPPROTO_IP, syscall.IP_BOUND_IF},
		{"udp6", "[::]:0", syscall.IPPROTO_IPV6, syscall.IPV6_BOUND_IF},
		// Family-less network: Go opens a dual-stack AF_INET6 socket even
		// for 0.0.0.0, which the old network-name switch left unbound.
		{"udp", ":0", syscall.IPPROTO_IPV6, syscall.IPV6_BOUND_IF},
		{"udp", "0.0.0.0:0", syscall.IPPROTO_IPV6, syscall.IPV6_BOUND_IF},
	} {
		t.Run(tc.network+"/"+tc.address, func(t *testing.T) {
			opts := &Options{InterfaceName: lo.Name}
			lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
				return setSocketOptions(network, address, c, opts)
			}}
			pc, err := lc.ListenPacket(context.Background(), tc.network, tc.address)
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()

			if got := boundIf(t, pc.(*net.UDPConn), tc.level, tc.option); got != lo.Index {
				t.Fatalf("bound interface = %d, want %d (%s)", got, lo.Index, lo.Name)
			}
		})
	}
}

func TestSetSocketOptionsSkipsScopedAddress(t *testing.T) {
	opts := &Options{InterfaceName: "lo0"}
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		return setSocketOptions(network, address, c, opts)
	}}
	pc, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	if got := boundIf(t, pc.(*net.UDPConn), syscall.IPPROTO_IP, syscall.IP_BOUND_IF); got != 0 {
		t.Fatalf("loopback listen socket bound to interface %d", got)
	}
}

func TestSetSocketOptionsListenerStaysUnbound(t *testing.T) {
	opts := &Options{InterfaceName: "lo0", listener: true}
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		return setSocketOptions(network, address, c, opts)
	}}
	pc, err := lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	if got := boundIf(t, pc.(*net.UDPConn), syscall.IPPROTO_IP, syscall.IP_BOUND_IF); got != 0 {
		t.Fatalf("inbound listener bound to interface %d", got)
	}
}

func boundIf(t *testing.T, conn *net.UDPConn, level, option int) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got int
	var sockErr error
	if err := raw.Control(func(fd uintptr) { got, sockErr = unix.GetsockoptInt(int(fd), level, option) }); err != nil {
		t.Fatal(err)
	}
	if sockErr != nil {
		t.Fatal(sockErr)
	}
	return got
}
