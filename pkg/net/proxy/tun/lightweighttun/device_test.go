package lightweighttun

import (
	"bytes"
	"errors"
	"io"
	"syscall"
	"testing"
)

type testTun struct {
	offset  int
	gso     bool
	packets [][]byte
	written []byte
	nextErr error
}

type writeResultTun struct {
	testTun
	count int
	err   error
}

func (d *writeResultTun) Write(b [][]byte) (int, error) {
	d.written = bytes.Clone(b[0])
	return d.count, d.err
}

func TestPacketDeviceAcceptedWriteIsNotRetried(t *testing.T) {
	for _, tc := range []struct {
		name  string
		count int
		err   error
		want  error
	}{
		{"accepted", 1, nil, nil},
		{"accepted-with-next-error", 1, syscall.EAGAIN, nil},
		{"unaccepted-transient", 0, syscall.EAGAIN, syscall.EAGAIN},
		{"short-without-error", 0, nil, io.ErrShortWrite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &writeResultTun{count: tc.count, err: tc.err}
			p, err := newPacketIO(d)
			if err != nil {
				t.Fatal(err)
			}
			err = p.WritePacket([]byte("packet"))
			if !errors.Is(err, tc.want) {
				t.Fatalf("accepted=%d: got %v, want %v", tc.count, err, tc.want)
			}
			if p.writeBuffers[0] != nil {
				t.Fatal("borrowed packet retained after synchronous write")
			}
		})
	}
}

func (d *testTun) Read(b [][]byte, sizes []int) (int, error) {
	if len(d.packets) == 0 {
		return 0, io.EOF
	}
	n := min(len(b), len(d.packets))
	for i := range n {
		sizes[i] = copy(b[i][d.offset:], d.packets[i])
	}
	d.packets = d.packets[n:]
	err := d.nextErr
	d.nextErr = nil
	return n, err
}
func (d *testTun) Write(b [][]byte) (int, error) { d.written = bytes.Clone(b[0]); return len(b), nil }
func (d *testTun) Close() error                  { return nil }
func (d *testTun) MTU() int                      { return 1500 }
func (d *testTun) Offset() int                   { return d.offset }
func (d *testTun) BatchSize() int                { return 2 }
func (d *testTun) GSOEnabled() bool              { return d.gso }

func TestPacketDeviceOffsetsAndOwnership(t *testing.T) {
	for _, offset := range []int{0, 4} {
		d := &testTun{offset: offset, packets: [][]byte{[]byte("first"), []byte("second")}}
		p, err := newPacketIO(d)
		if err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 32)
		for _, want := range []string{"first", "second"} {
			n, err := p.ReadPacket(b)
			if err != nil || string(b[:n]) != want {
				t.Fatalf("batch packet %q %v", b[:n], err)
			}
		}
		data := []byte("owned output")
		if err = p.WritePacket(data); err != nil {
			t.Fatal(err)
		}
		clear(data)
		if !bytes.Equal(d.written[offset:], []byte("owned output")) {
			t.Fatal("device output aliases caller memory")
		}
	}
	if _, err := newPacketIO(&testTun{gso: true}); err == nil {
		t.Fatal("accepted unvalidated offload")
	}
}

func TestPacketDeviceDrainsPartialBatchBeforeError(t *testing.T) {
	d := &testTun{packets: [][]byte{[]byte("first"), []byte("second")}, nextErr: io.EOF}
	p, err := newPacketIO(d)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 100)
	for _, want := range []string{"first", "second"} {
		n, err := p.ReadPacket(b)
		if err != nil || string(b[:n]) != want {
			t.Fatalf("batch data %q %v", b[:n], err)
		}
	}
	if _, err := p.ReadPacket(b); err != io.EOF {
		t.Fatalf("pending batch error: %v", err)
	}
}
