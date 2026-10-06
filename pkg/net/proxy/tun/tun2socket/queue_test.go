package tun2socket

import (
	"bytes"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type queueTestTun struct {
	queues    []chan []byte
	written   chan []byte
	closed    chan struct{}
	closeOnce sync.Once
	failQueue bool
}

func newQueueTestTun() *queueTestTun {
	return &queueTestTun{
		queues:  []chan []byte{make(chan []byte, 1), make(chan []byte, 1)},
		written: make(chan []byte, 2), closed: make(chan struct{}),
	}
}

func (*queueTestTun) BatchSize() int        { return 1 }
func (*queueTestTun) Offset() int           { return 0 }
func (*queueTestTun) MTU() int              { return 1500 }
func (*queueTestTun) GSOEnabled() bool      { return false }
func (d *queueTestTun) ReadQueueCount() int { return len(d.queues) }
func (d *queueTestTun) Read(bufs [][]byte, sizes []int) (int, error) {
	return d.ReadQueue(0, bufs, sizes)
}
func (d *queueTestTun) ReadQueue(queue int, bufs [][]byte, sizes []int) (int, error) {
	if d.failQueue && queue == 0 {
		return 0, io.EOF
	}
	select {
	case packet := <-d.queues[queue]:
		sizes[0] = copy(bufs[0], packet)
		return 1, nil
	case <-d.closed:
		return 0, os.ErrClosed
	}
}
func (d *queueTestTun) Write(bufs [][]byte) (int, error) {
	for _, b := range bufs {
		d.written <- bytes.Clone(b)
	}
	return len(bufs), nil
}
func (d *queueTestTun) Close() error {
	d.closeOnce.Do(func() { close(d.closed) })
	return nil
}

func startTestQueueReaders(t *testing.T, tun netlink.Tun) (*Nat, <-chan struct{}) {
	t.Helper()
	n := &Nat{
		UDP: &UDP{}, tab: newTable(), gatewayPort: 1234,
		InterfaceAddress: device.InterfaceAddress{
			Addressv4: tcpip.AddrFrom4([4]byte{172, 19, 0, 1}),
			Portalv4:  tcpip.AddrFrom4([4]byte{172, 19, 0, 2}),
		},
	}
	done := make(chan struct{})
	go func() {
		n.readTunQueues(&device.Opt{Options: &netlink.Options{Device: tun, MTU: 1500}},
			tcpip.Address{}, tcpip.Address{}, tcpip.Address{})
		close(done)
	}()
	t.Cleanup(func() {
		n.UDP.Close()
		tun.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("TUN readers did not stop after device Close")
		}
		n.tab.Close()
	})
	return n, done
}

func TestSystemQueueReadersDeliverTCPBeforeNextRead(t *testing.T) {
	for _, single := range []bool{false, true} {
		name := "multiple queues"
		if single {
			name = "single queue"
		}
		t.Run(name, func(t *testing.T) {
			d := newQueueTestTun()
			var tun netlink.Tun = d
			queue := 1
			if single {
				// Hide the optional queue API, as on externally supplied FDs.
				tun = struct{ netlink.Tun }{d}
				queue = 0
			}
			n, _ := startTestQueueReaders(t, tun)
			packet := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize+1)
			header.IPv4(packet).Encode(&header.IPv4Fields{
				TotalLength: uint16(len(packet)), Protocol: uint8(header.TCPProtocolNumber), TTL: 64,
				SrcAddr: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}),
				DstAddr: tcpip.AddrFrom4([4]byte{198, 18, 0, 1}),
			})
			header.TCP(packet[header.IPv4MinimumSize:]).Encode(&header.TCPFields{
				SrcPort: 54321, DstPort: 443, DataOffset: header.TCPMinimumSize, Flags: header.TCPFlagAck,
			})
			packet[len(packet)-1] = 42
			// No later packet arrives. In the multiqueue case, queue 0 stays idle.
			d.queues[queue] <- packet
			select {
			case got := <-d.written:
				ip := header.IPv4(got)
				tcp := header.TCP(ip.Payload())
				if ip.DestinationAddress() != n.Addressv4 || ip.SourceAddress() != n.Portalv4 ||
					tcp.DestinationPort() != n.gatewayPort || !bytes.Equal(tcp.Payload(), []byte{42}) {
					t.Fatal("TCP packet was not translated and delivered intact")
				}
			case <-time.After(time.Second):
				t.Fatal("TCP packet stalled behind an idle queue or the next read")
			}
		})
	}
}

func TestSystemQueueReadFailureReleasesOtherReaders(t *testing.T) {
	d := newQueueTestTun()
	d.failQueue = true
	_, done := startTestQueueReaders(t, d)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed queue left other TUN readers blocked")
	}
}
