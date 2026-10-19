//go:build (((linux && !android) || darwin) && (amd64 || arm64)) || (windows && amd64) || (android && arm64 && cgo)

package zerotier

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	zt "github.com/yuhaiin/zerotier-go"
)

type packetOutbound struct {
	conn        net.PacketConn
	bindAddress string
	remote      netapi.Address
}

func (p *packetOutbound) PacketConn(ctx context.Context, remote netapi.Address) (net.PacketConn, error) {
	p.bindAddress = netapi.GetContext(ctx).ConnOptions().BindAddress()
	p.remote = remote
	return p.conn, nil
}

func TestOpenUnderlayUsesRootPacketConn(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	outbound := &packetOutbound{conn: conn}
	got, err := openUnderlay(outbound, ":19993")
	if err != nil {
		t.Fatal(err)
	}
	if got != conn {
		t.Fatal("underlay did not use the root outbound packet connection")
	}
	if outbound.bindAddress != ":19993" {
		t.Fatalf("bind address = %q, want %q", outbound.bindAddress, ":19993")
	}
	if outbound.remote.Network() != "udp" {
		t.Fatalf("remote network = %q, want udp", outbound.remote.Network())
	}
}

func TestSendWireWritesEncryptedDatagramToNativeDestination(t *testing.T) {
	underlay, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = underlay.Close() })
	target, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Close() })

	client := &Client{underlay: underlay}
	packet := zt.WirePacket{
		To:   target.LocalAddr().(*net.UDPAddr).AddrPort(),
		Data: []byte("encrypted-zerotier-packet"),
	}
	if err := client.sendWire(packet); err != nil {
		t.Fatal(err)
	}
	if err := target.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, from, err := target.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(packet.Data) {
		t.Fatalf("packet payload = %q, want %q", buf[:n], packet.Data)
	}
	if from.String() != underlay.LocalAddr().String() {
		t.Fatalf("packet source = %q, want %q", from, underlay.LocalAddr())
	}
}

func TestReadWirePacketsPassesSourceAndPayload(t *testing.T) {
	receiver, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = receiver.Close() })
	sender, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sender.Close() })

	type receivedPacket struct {
		from netip.AddrPort
		data []byte
	}
	received := make(chan receivedPacket, 1)
	done := make(chan struct{})
	go func() {
		readWirePackets(receiver, func(from netip.AddrPort, data []byte) error {
			received <- receivedPacket{from: from, data: append([]byte(nil), data...)}
			return nil
		})
		close(done)
	}()

	want := []byte("reply-from-underlay")
	if _, err := sender.WriteTo(want, receiver.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		if got.from != sender.LocalAddr().(*net.UDPAddr).AddrPort() {
			t.Fatalf("source = %s, want %s", got.from, sender.LocalAddr())
		}
		if string(got.data) != string(want) {
			t.Fatalf("payload = %q, want %q", got.data, want)
		}
	case <-time.After(time.Second):
		t.Fatal("underlay receive loop did not process the packet")
	}
	_ = receiver.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("underlay receive loop did not stop after socket close")
	}
}

func TestApplyConfigIgnoresQueuedConfigAfterClose(t *testing.T) {
	closing := make(chan struct{})
	close(closing)
	client := &Client{closing: closing}
	client.applyConfig(zt.NetworkConfig{
		ID: 1, MAC: 1, Status: zt.NetworkOK, Operation: zt.NetworkUp, MTU: 1400,
		Addresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
	})
	if client.active != nil {
		t.Fatal("network configuration installed a session after close started")
	}
}

func TestInstallSessionRejectsSessionAfterClose(t *testing.T) {
	closing := make(chan struct{})
	close(closing)
	client := &Client{closing: closing}

	if old, installed := client.installSession(&session{}); installed || old != nil {
		t.Fatal("session was installed after close started")
	}
	if client.active != nil {
		t.Fatal("active session changed after close started")
	}
}
