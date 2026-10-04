package device

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"

	wun "github.com/tailscale/wireguard-go/tun"
)

type slabTestDevice struct {
	wun.Device
	payloads [][]byte
	err      error
}

func (d *slabTestDevice) BatchSize() int { return len(d.payloads) }

func (d *slabTestDevice) Read(slab []byte, packets []wun.ReadPacket) (int, error) {
	offset := wun.ReadPacketSpacing
	for i, payload := range d.payloads {
		if offset+len(payload)+wun.ReadPacketSpacing > len(slab) {
			return i, wun.ErrTooManySegments
		}
		copy(slab[offset:], payload)
		packets[i] = wun.ReadPacket{Offset: offset, Size: len(payload)}
		offset += len(payload) + wun.ReadPacketSpacing
	}
	return len(d.payloads), d.err
}

func TestDeviceReadSlab(t *testing.T) {
	for _, offset := range []int{0, 4, 10} {
		for _, readErr := range []error{nil, io.EOF} {
			t.Run(fmt.Sprintf("offset=%d/error=%v", offset, readErr), func(t *testing.T) {
				payloads := [][]byte{[]byte("first packet"), []byte("second")}
				d := NewDevice(&slabTestDevice{payloads: payloads, err: readErr}, offset, 1500, false)
				bufs := [][]byte{bytes.Repeat([]byte{0xaa}, 32+offset), bytes.Repeat([]byte{0xaa}, 32+offset)}
				sizes := make([]int, len(bufs))
				for range 2 {
					n, err := d.Read(bufs, sizes)
					if n != len(payloads) || !errors.Is(err, readErr) {
						t.Fatalf("Read() = %d, %v", n, err)
					}
					for i, payload := range payloads {
						if sizes[i] != len(payload) || !bytes.Equal(bufs[i][offset:offset+sizes[i]], payload) {
							t.Fatalf("packet %d: size=%d buf=%x", i, sizes[i], bufs[i])
						}
						if !bytes.Equal(bufs[i][:offset], bytes.Repeat([]byte{0xaa}, offset)) {
							t.Fatalf("packet %d: prefix overwritten", i)
						}
					}
				}
			})
		}
	}
}

func TestDeviceReadShortBuffer(t *testing.T) {
	d := NewDevice(&slabTestDevice{payloads: [][]byte{[]byte("fits"), []byte("too long")}}, 4, 1500, false)
	bufs := [][]byte{make([]byte, 36), make([]byte, 5)}
	sizes := make([]int, 2)
	n, err := d.Read(bufs, sizes)
	if n != 1 || !errors.Is(err, io.ErrShortBuffer) || sizes[0] != 4 {
		t.Fatalf("Read() = %d, %v, sizes=%v", n, err, sizes)
	}
	if n, err := d.Read(bufs[:1], sizes[:1]); n != 0 || !errors.Is(err, wun.ErrTooManySegments) {
		t.Fatalf("undersized batch: Read() = %d, %v", n, err)
	}
}
