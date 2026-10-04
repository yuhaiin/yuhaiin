package gvisor

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
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
