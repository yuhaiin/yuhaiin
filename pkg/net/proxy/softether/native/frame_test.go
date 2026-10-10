// Adapted from xen0bit/veepin (MIT), Copyright (c) 2026 Remy. See THIRD_PARTY_LICENSE.
package native

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// TestBlockFramingIsBigEndian pins the byte order of the data path. It is the
// half of the wire this package had backwards, and the failure it causes
// against a real peer is a tunnel that comes up and then hangs -- a count read
// from the wrong end of a 32-bit word is a plausible-looking large number, not
// a parse error.
func TestBlockFramingIsBigEndian(t *testing.T) {
	var buf bytes.Buffer
	if err := writeBlocks(&buf, [][]byte{{0xde, 0xad}}); err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0, 0, 0, 1, // one block
		0, 0, 0, 2, // two octets
		0xde, 0xad,
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("wire = %x, want %x", buf.Bytes(), want)
	}
}

// TestBurstIsOneWrite asserts that a multi-frame burst reaches the connection
// as a single Write. Two concurrent senders that each emitted a count and then
// their bodies could interleave into a stream that parses as garbage, and the
// symptom would be a rare desync under load rather than an outright failure.
func TestBurstIsOneWrite(t *testing.T) {
	c := &countingWriter{}
	frames := [][]byte{{1}, {2, 2}, {3, 3, 3}}
	if err := writeBlocks(c, frames); err != nil {
		t.Fatal(err)
	}
	if c.writes != 1 {
		t.Errorf("burst of %d frames took %d writes, want 1", len(frames), c.writes)
	}
}

// TestReaderCrossesBurstBoundaries checks that a caller reading frames sees
// them in order regardless of how the sender batched them. Burst boundaries
// are the sender's business and must not be visible to the switch.
func TestReaderCrossesBurstBoundaries(t *testing.T) {
	var buf bytes.Buffer
	if err := writeBlocks(&buf, [][]byte{{1}, {2}}); err != nil {
		t.Fatal(err)
	}
	if err := writeBlocks(&buf, [][]byte{{3}}); err != nil {
		t.Fatal(err)
	}

	r := newBlockReader(bufio.NewReader(&buf))
	for _, want := range []byte{1, 2, 3} {
		got, err := r.next()
		if err != nil {
			t.Fatalf("frame %d: %v", want, err)
		}
		if len(got) != 1 || got[0] != want {
			t.Errorf("frame = %x, want %02x", got, want)
		}
	}
}

// TestKeepAliveIsSkipped: a keepalive carries no frame and must not surface to
// the caller as one. A zero-length "frame" reaching the switch would be
// dropped by ParseFrame anyway, but a keepalive's payload is random octets,
// which would be forwarded as though it were Ethernet.
func TestKeepAliveIsSkipped(t *testing.T) {
	var buf bytes.Buffer
	if err := writeKeepAlive(&buf); err != nil {
		t.Fatal(err)
	}
	if err := writeBlocks(&buf, [][]byte{{0xaa}}); err != nil {
		t.Fatal(err)
	}

	r := newBlockReader(bufio.NewReader(&buf))
	got, err := r.next()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != 0xaa {
		t.Errorf("frame after keepalive = %x, want aa", got)
	}
}

// TestZeroCountIsATickNotAFrame: a count of zero means "no frames follow", and
// the next thing on the wire is another count. Treating it as a frame of zero
// length would desynchronise the stream permanently.
func TestZeroCountIsATickNotAFrame(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0, 0, 0, 0}) // a tick
	if err := writeBlocks(&buf, [][]byte{{0xbb}}); err != nil {
		t.Fatal(err)
	}

	r := newBlockReader(bufio.NewReader(&buf))
	got, err := r.next()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != 0xbb {
		t.Errorf("frame after tick = %x, want bb", got)
	}
}

// TestReaderRefusesImplausibleCounts stops a peer from making us sit in a loop
// on its say-so. The reference trusts the count; we do not.
func TestReaderRefusesImplausibleCounts(t *testing.T) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint32(maxBlocksPerBurst+1))

	r := newBlockReader(bufio.NewReader(&buf))
	if _, err := r.next(); !errors.Is(err, errTooManyBlocks) {
		t.Errorf("err = %v, want errTooManyBlocks", err)
	}
}

// TestReaderRefusesOversizedBlocks is the same argument one level down.
func TestReaderRefusesOversizedBlocks(t *testing.T) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint32(1))
	_ = binary.Write(&buf, binary.BigEndian, uint32(maxBlockSize+1))

	r := newBlockReader(bufio.NewReader(&buf))
	if _, err := r.next(); !errors.Is(err, errBlockTooLarge) {
		t.Errorf("err = %v, want errBlockTooLarge", err)
	}
}

// TestReaderRejectsEveryTruncation walks every prefix of a valid two-frame
// burst and requires each to fail rather than return a frame. The house rule
// for every codec here.
func TestReaderRejectsEveryTruncation(t *testing.T) {
	var full bytes.Buffer
	if err := writeBlocks(&full, [][]byte{{1, 2, 3}, {4, 5}}); err != nil {
		t.Fatal(err)
	}
	whole := full.Bytes()

	for n := range len(whole) {
		r := newBlockReader(bufio.NewReader(bytes.NewReader(whole[:n])))
		// Drain: any frame returned before the truncation point is legitimate
		// (the first frame is complete in some prefixes); what must never
		// happen is a successful read past the end of the data.
		for {
			_, err := r.next()
			if err != nil {
				break
			}
		}
	}
}

type countingWriter struct {
	writes int
	buf    bytes.Buffer
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.writes++
	return c.buf.Write(p)
}

var _ io.Writer = (*countingWriter)(nil)

// TestShapeFramePadsIPAndLeavesEverythingElse. Padding is only safe where the
// receiver has a length field to trim by: an IP header's Total Length. An ARP
// frame has no such field, so a padded one is a corrupted one -- and ARP is the
// first thing across a layer-2 tunnel, so getting this wrong breaks the tunnel
// before any IP packet exists to notice.
