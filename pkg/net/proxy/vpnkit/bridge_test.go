package vpnkit

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/internal/testutil"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"
	vpnclient "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/session"
)

func TestBridgeAssignedStackAndPacketOwnership(t *testing.T) {
	b := newPacketBridge()
	defer b.Close()
	type received struct {
		data []byte
		err  error
	}
	outgoing := make(chan received, 1)
	// Protocol engines may begin reading before their negotiated IP arrives.
	go func() { data := make([]byte, 1500); n, err := b.Read(data); outgoing <- received{data[:n], err} }()
	network, err := b.Attach(vpnclient.Result{AssignedIP: net.IPv4(192, 0, 2, 1), MTU: 576})
	if err != nil {
		t.Fatal(err)
	}
	socket, err := network.DialUDP(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	_ = socket.SetDeadline(time.Now().Add(time.Second))
	remote := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 53}
	if _, err := socket.WriteTo([]byte("request"), remote); err != nil {
		t.Fatal(err)
	}
	select {
	case sent := <-outgoing:
		if sent.err != nil {
			t.Fatal(sent.err)
		}
		p, err := lightweight.ParsePacket(sent.data)
		if err != nil || p.Source.String() != "192.0.2.1" || p.Destination.String() != "192.0.2.2" || p.Protocol != 17 {
			t.Fatalf("invalid bridge packet: %v %v", p, err)
		}
	case <-time.After(time.Second):
		t.Fatal("pre-assignment read did not resume")
	}
	reply := testutil.IPv4UDP(remote.IP, net.IPv4(192, 0, 2, 1), uint16(remote.Port), uint16(socket.LocalAddr().(*net.UDPAddr).Port), []byte("reply"))
	if n, err := b.Write(reply); err != nil || n != len(reply) {
		t.Fatalf("bridge write=%d, %v", n, err)
	}
	clear(reply) // The engine is entitled to reuse its input immediately.
	buf := make([]byte, 64)
	n, from, err := socket.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "reply" || from.String() != remote.String() {
		t.Fatalf("reply=%q from=%v err=%v", buf[:n], from, err)
	}
	if _, err := b.Attach(vpnclient.Result{AssignedIP: remote.IP, MTU: 576}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("second attachment accepted: %v", err)
	}
}
func TestBridgeCloseBeforeAssignment(t *testing.T) {
	b := newPacketBridge()
	done := make(chan error, 2)
	go func() { _, err := b.Read(make([]byte, 1500)); done <- err }()
	go func() { _, err := b.Write([]byte{0x45}); done <- err }()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		select {
		case err := <-done:
			if !errors.Is(err, io.ErrClosedPipe) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("unassigned bridge did not unblock")
		}
	}
}
