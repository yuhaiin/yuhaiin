package wireguard

import (
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/gvisor"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type closeNotifyingDevice struct {
	netlink.Tun
	closed chan struct{}
}

func (d *closeNotifyingDevice) Close() error {
	close(d.closed)
	return d.Tun.Close()
}

type shutdownDispatcher struct {
	stack   *stack.Stack
	entered chan struct{}
	closed  <-chan struct{}
}

func (*shutdownDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

func (d *shutdownDispatcher) DeliverNetworkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
	close(d.entered)
	<-d.closed
	// IPv6 reception looks up the NIC name under the stack read lock.
	// Force that lookup to overlap shutdown while a packet is in flight.
	d.stack.FindNICNameFromID(1)
}

func TestNetTunCloseWithPacketInFlight(t *testing.T) {
	channel := NewChannelDevice(t.Context(), 1400)
	d := &closeNotifyingDevice{Tun: device.NewDevice(channel, 0, 1400, false), closed: make(chan struct{})}
	n := &NetTun{dev: channel, ep: gvisor.NewEndpoint(d), stack: stack.New(stack.Options{})}
	dispatcher := &shutdownDispatcher{stack: n.stack, entered: make(chan struct{}), closed: d.closed}
	n.ep.Attach(dispatcher)
	if err := n.stack.CreateNIC(1, n.ep); err != nil {
		t.Fatal(err)
	}
	if err := channel.Outbound([]byte{0x60}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dispatcher.entered:
	case <-time.After(time.Second):
		t.Fatal("packet did not reach dispatcher")
	}
	done := make(chan struct{})
	go func() {
		_ = n.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close deadlocked with an in-flight stack lookup")
	}
	// Closing again must not close the device or destroy the stack twice.
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
}
