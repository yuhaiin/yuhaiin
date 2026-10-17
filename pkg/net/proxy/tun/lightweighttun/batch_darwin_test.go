//go:build darwin && !ios

package lightweighttun

import (
	"errors"
	"io"
	"syscall"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"
)

type batchDevice struct {
	testTun
	calls int
	first *byte
}

func (*batchDevice) BatchSize() int                 { return 16 }
func (*batchDevice) ExperimentalUTUNBatchSize() int { return 16 }
func (d *batchDevice) Write(b [][]byte) (int, error) {
	d.calls++
	d.first = &b[0][0]
	return 3, syscall.EAGAIN
}
func TestDarwinPacketBatchBorrowsBuffersAndPreservesPrefix(t *testing.T) {
	d := &batchDevice{offset: 4}
	p, e := NewPacketIO(d)
	if e != nil {
		t.Fatal(e)
	}
	w, ok := p.(lightweight.PacketBatchWriter)
	if !ok {
		t.Fatal("Darwin experiment did not negotiate batching")
	}
	packets := make([]lightweight.PacketBuffer, 16)
	for i := range packets {
		packets[i] = lightweight.PacketBuffer{Data: make([]byte, 64), Offset: 4}
	}
	n, e := w.WritePacketBatch(packets)
	if n != 3 || !errors.Is(e, syscall.EAGAIN) || d.calls != 1 || d.first != &packets[0].Data[0] {
		t.Fatal("copied buffers or lost accepted prefix", n, e)
	}
	for _, b := range p.(*utunPacketIO).bufs {
		if b != nil {
			t.Fatal("retained borrowed buffer")
		}
	}
	packets[1].Offset = 0
	if n, e := w.WritePacketBatch(packets); n != 0 || !errors.Is(e, io.ErrShortBuffer) {
		t.Fatal(n, e)
	}
	if d.calls != 1 {
		t.Fatal("invalid batch reached device")
	}
}
func TestOrdinaryDarwinDeviceKeepsSinglePacketWriter(t *testing.T) {
	p, e := NewPacketIO(&testTun{offset: 4})
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := p.(lightweight.PacketBatchWriter); ok {
		t.Fatal("ordinary device behavior changed")
	}
}
