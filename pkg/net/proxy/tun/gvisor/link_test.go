package gvisor

import (
	"bytes"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type packetTestTun struct {
	offset  int
	written [][]byte
	err     error
	count   int
}

func (d *packetTestTun) BatchSize() int                    { return 1 }
func (d *packetTestTun) Offset() int                       { return d.offset }
func (d *packetTestTun) MTU() int                          { return 1500 }
func (d *packetTestTun) GSOEnabled() bool                  { return false }
func (d *packetTestTun) Close() error                      { return nil }
func (d *packetTestTun) Read([][]byte, []int) (int, error) { return 0, io.EOF }
func (d *packetTestTun) Write(bufs [][]byte) (int, error) {
	for _, b := range bufs {
		d.written = append(d.written, bytes.Clone(b[d.offset:]))
	}
	if d.err != nil {
		return d.count, d.err
	}
	return len(bufs), nil
}

func testPacketList(n int) stack.PacketBufferList {
	var packets stack.PacketBufferList
	for i := range n {
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: 5, Payload: buffer.MakeWithData(bytes.Repeat([]byte{byte(i)}, 1500))})
		copy(p.NetworkHeader().Push(3), []byte{1, 2, 3})
		copy(p.TransportHeader().Push(2), []byte{4, 5})
		packets.PushBack(p)
	}
	return packets
}

func TestWritePacketsPreservesViewsAndOffset(t *testing.T) {
	for _, offset := range []int{0, 4} {
		d := &packetTestTun{offset: offset}
		e := NewEndpoint(d)
		packets := testPacketList(3)
		defer packets.Reset()
		for range 3 {
			d.written = nil
			n, err := e.WritePackets(packets)
			if err != nil || n != 3 {
				t.Fatalf("n=%d err=%v", n, err)
			}
			for i, p := range packets.AsSlice() {
				view := p.ToView()
				want := bytes.Clone(view.AsSlice())
				view.Release()
				if !bytes.Equal(d.written[i], want) {
					t.Fatal("packet headers/payload corrupted")
				}
			}
		}
		d.err = errors.New("short write")
		d.count = 1
		if n, _ := e.WritePackets(packets); n != 1 {
			t.Fatalf("short write count=%d", n)
		}
		e.Close()
		if _, err := e.WritePackets(packets); err == nil {
			t.Fatal("closed endpoint accepted packets")
		}
	}
}

type discardPacketTun struct{ packetTestTun }

func (d *discardPacketTun) Write(bufs [][]byte) (int, error) { return len(bufs), nil }

func BenchmarkWritePackets(b *testing.B) {
	for _, n := range []int{1, 8, 64} {
		name := map[int]string{1: "1", 8: "8", 64: "64"}[n]
		b.Run(name, func(b *testing.B) {
			e := NewEndpoint(&discardPacketTun{})
			packets := testPacketList(n)
			defer packets.Reset()
			b.SetBytes(int64(1505 * n))
			b.ReportAllocs()
			for b.Loop() {
				_, err := e.WritePackets(packets)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

type queuedPacketTun struct {
	packetTestTun
	queues    []chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func newQueuedPacketTun(n int) *queuedPacketTun {
	d := &queuedPacketTun{queues: make([]chan []byte, n), closed: make(chan struct{})}
	for i := range d.queues {
		d.queues[i] = make(chan []byte, 1)
	}
	return d
}

func (d *queuedPacketTun) GSOEnabled() bool    { return true }
func (d *queuedPacketTun) ReadQueueCount() int { return len(d.queues) }
func (d *queuedPacketTun) ReadQueue(queue int, bufs [][]byte, sizes []int) (int, error) {
	select {
	case packet := <-d.queues[queue]:
		sizes[0] = copy(bufs[0], packet)
		return 1, nil
	case <-d.closed:
		return 0, os.ErrClosed
	}
}

func (d *queuedPacketTun) Read(bufs [][]byte, sizes []int) (int, error) {
	// The old channel endpoint blocks here on queue 0, ignoring queue 1.
	return d.ReadQueue(0, bufs, sizes)
}

func (d *queuedPacketTun) Close() error {
	d.closeOnce.Do(func() { close(d.closed) })
	return nil
}

type packetDispatcher struct{ received chan []byte }

func (d *packetDispatcher) DeliverNetworkPacket(_ tcpip.NetworkProtocolNumber, p *stack.PacketBuffer) {
	d.received <- p.Data().AsRange().ToSlice()
}

func (*packetDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

func TestChannelEndpointDrainsEveryQueue(t *testing.T) {
	d := newQueuedPacketTun(2)
	e := NewEndpoint(d)
	t.Cleanup(e.Close)
	dispatcher := &packetDispatcher{received: make(chan []byte, 2)}
	e.Attach(dispatcher)
	// Leave queue 0 idle. A packet on queue 1 must not wait for queue 0.
	packet := make([]byte, header.IPv4MinimumSize)
	packet[0] = 0x45
	d.queues[1] <- packet
	select {
	case got := <-dispatcher.received:
		if !bytes.Equal(got, packet) {
			t.Fatal("packet corrupted")
		}
	case <-time.After(time.Second):
		t.Fatal("active TUN queue starved behind idle queue")
	}
}

func TestChannelEndpointFlushesGROBeforeNextRead(t *testing.T) {
	d := newQueuedPacketTun(1)
	// Hide the optional queue API to cover single-queue/FD devices as well.
	e := NewEndpoint(struct{ netlink.Tun }{d})
	t.Cleanup(e.Close)
	dispatcher := &packetDispatcher{received: make(chan []byte, 2)}
	e.Attach(dispatcher)
	packet := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize+1)
	header.IPv4(packet).Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		Protocol:    uint8(header.TCPProtocolNumber), TTL: 64,
		SrcAddr: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), DstAddr: tcpip.AddrFrom4([4]byte{192, 0, 2, 2}),
	})
	header.TCP(packet[header.IPv4MinimumSize:]).Encode(&header.TCPFields{
		SrcPort: 1234, DstPort: 80, SeqNum: 1, AckNum: 1,
		DataOffset: header.TCPMinimumSize, Flags: header.TCPFlagAck, WindowSize: 1024,
	})
	packet[len(packet)-1] = 42
	d.queues[0] <- packet
	select {
	case got := <-dispatcher.received:
		if !bytes.Equal(got, packet) {
			t.Fatal("GRO packet corrupted")
		}
	case <-time.After(time.Second):
		t.Fatal("GRO packet retained while next TUN read blocks")
	}
}

type failingQueueTun struct{ *queuedPacketTun }

func (d *failingQueueTun) ReadQueue(queue int, bufs [][]byte, sizes []int) (int, error) {
	if queue == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	return d.queuedPacketTun.ReadQueue(queue, bufs, sizes)
}

func TestChannelEndpointReadFailureReleasesOtherQueues(t *testing.T) {
	d := &failingQueueTun{newQueuedPacketTun(2)}
	t.Cleanup(func() { _ = d.Close() })
	e := NewEndpoint(d)
	e.Attach(&packetDispatcher{received: make(chan []byte, 2)})
	select {
	case <-d.closed:
	case <-time.After(time.Second):
		t.Fatal("failed TUN queue left other readers blocked")
	}
	done := make(chan struct{})
	go func() {
		e.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not wait for all TUN readers to exit")
	}
}
