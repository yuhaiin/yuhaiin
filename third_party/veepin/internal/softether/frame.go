package softether

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/xen0bit/veepin/dataplane"
)

// The SE-VPN data path, once the control PACKs are done with.
//
// Frames are not written one per length prefix. They are written in *blocks*:
// a count, then that many length-and-body pairs, all big-endian.
//
//	+--------------------------------------------------+
//	| block count (uint32, big-endian)                  |
//	+--------------------------------------------------+
//	| size (uint32) | Ethernet frame (size octets)      |  × count
//	+--------------------------------------------------+
//
// Two counts are not counts:
//
//   - **0** means no frames follow. The next thing on the connection is
//     another count. The reference sends these as a liveness tick.
//   - **0xffffffff** (KEEP_ALIVE_MAGIC) introduces one size and that many
//     octets of random padding, which is discarded. It is a keepalive whose
//     length is deliberately variable so that an observer cannot use "a
//     fixed-size record every N seconds" as a fingerprint.
//
// This package previously wrote one little-endian length per frame and no
// count at all. Two veepin endpoints agreed with each other about that
// perfectly; a SoftEther server reads the first four octets of such a stream
// as a block count of 0x8a050000 and waits for 2.3 billion frames that never
// come. Nothing times out, nothing errors -- the tunnel comes up and hangs,
// which is why the veepin-to-veepin cell was green.
//
// The blocking is also the reason this is worth doing properly rather than
// sending count=1 every time: a burst of frames costs one count for the whole
// burst, and the reference's own sender batches whatever its queue holds.

// keepAliveMagic is Cedar.h's KEEP_ALIVE_MAGIC.
const keepAliveMagic = 0xffffffff

// maxBlockSize is the per-block bound the reference enforces on receive,
// MAX_PACKET_SIZE * 2 from Cedar.h. It is generous next to MaxFrameSize on
// purpose: a peer is allowed to send a jumbo-ish frame and be told no, rather
// than have the connection dropped for a framing error it did not commit.
const maxBlockSize = 1600 * 2

// maxBlocksPerBurst bounds a single count. The reference has no explicit
// limit -- it trusts the count and loops -- but an unbounded count read off
// the wire is an invitation to allocate on a peer's say-so, and no honest
// sender batches anywhere near this many.
const maxBlocksPerBurst = 4096

var (
	errBlockTooLarge = errors.New("softether: data block over the size limit")
	errTooManyBlocks = errors.New("softether: implausible block count")
)

// writeBlocks writes one burst: the count, then each frame with its size.
//
// Writing the whole burst into one buffer before it touches the connection is
// not tidiness. The peer reads a count and then loops reading exactly that
// many blocks, so a burst that reaches it in pieces with a TLS record boundary
// mid-block is still correct -- but a burst interleaved with another
// goroutine's is not, and one Write of one buffer is what makes interleaving
// impossible rather than merely unlikely.
func writeBlocks(w io.Writer, frames [][]byte) error {
	if len(frames) == 0 {
		return nil
	}
	if len(frames) > maxBlocksPerBurst {
		return fmt.Errorf("%w: %d", errTooManyBlocks, len(frames))
	}

	size := 4
	for _, f := range frames {
		size += 4 + len(f)
	}
	buf := make([]byte, 0, size)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(frames)))
	for _, f := range frames {
		if len(f) > maxBlockSize {
			return fmt.Errorf("%w: %d octets", errBlockTooLarge, len(f))
		}
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(f)))
		buf = append(buf, f...)
	}
	_, err := w.Write(buf)
	return err
}

// shapeFrame pads an Ethernet frame out to the shaper's target for its flow.
//
// The receiver trims it by the inner IP header's own Total Length, which is
// what every IP stack does with a short frame carrying a shorter datagram --
// the same mechanism internal/l2tpv3 relies on, and the reason a stock peer
// needs no support for this. A frame carrying anything but IP is returned
// untouched: there is no length field to trim by, and padding an ARP frame
// would corrupt it.
//
// The padding is zeros rather than random bytes. It is inside TLS, so an
// observer sees neither; zeros keep the append allocation-free of any entropy
// call on the data path, and a receiver that does look will see the filler for
// what it is rather than mistaking it for a truncated packet.
func shapeFrame(frame []byte, shaper *dataplane.Shaper, mtu int) []byte {
	target := shaper.TargetFrame(frame, mtu)
	if target <= len(frame) {
		return frame
	}
	out := make([]byte, target)
	copy(out, frame)
	return out
}

// writeKeepAlive sends a KEEP_ALIVE_MAGIC block with a random-length payload.
func writeKeepAlive(w io.Writer) error {
	var r [2]byte
	if _, err := rand.Read(r[:]); err != nil {
		return err
	}
	// The reference picks its padding under KEEP_MAX_PACKET_SIZE (128).
	n := int(binary.BigEndian.Uint16(r[:])) % 128
	pad := make([]byte, n)
	if _, err := rand.Read(pad); err != nil {
		return err
	}

	buf := make([]byte, 0, 8+n)
	buf = binary.BigEndian.AppendUint32(buf, keepAliveMagic)
	buf = binary.BigEndian.AppendUint32(buf, uint32(n))
	buf = append(buf, pad...)
	_, err := w.Write(buf)
	return err
}

// blockReader reads bursts off a connection, handing back one frame at a time.
//
// It holds the position within a burst, so a caller reads frames without
// caring where the burst boundaries fall -- which is what the data path wants,
// since a burst is a batching artefact of the sender and means nothing to the
// switch.
type blockReader struct {
	br        *bufio.Reader
	remaining uint32 // blocks left in the burst being read
	buf       []byte // reused frame buffer; a frame is valid until the next read
}

func newBlockReader(br *bufio.Reader) *blockReader {
	return &blockReader{br: br, buf: make([]byte, maxBlockSize)}
}

// next returns the next Ethernet frame.
//
// The returned slice aliases the reader's own buffer and stays valid only
// until the following call, which is the same contract every parser in this
// tree offers -- the inbound path is allocation-free by design and a copy here
// would cost one allocation per frame.
func (r *blockReader) next() ([]byte, error) {
	for {
		if r.remaining == 0 {
			count, err := r.readUint32()
			if err != nil {
				return nil, err
			}
			switch {
			case count == keepAliveMagic:
				if err := r.discardOne(); err != nil {
					return nil, err
				}
				continue
			case count == 0:
				// A tick with no frames. Read the next count.
				continue
			case count > maxBlocksPerBurst:
				return nil, fmt.Errorf("%w: %d", errTooManyBlocks, count)
			}
			r.remaining = count
		}

		size, err := r.readUint32()
		if err != nil {
			return nil, err
		}
		r.remaining--
		if size > maxBlockSize {
			return nil, fmt.Errorf("%w: %d octets", errBlockTooLarge, size)
		}
		frame := r.buf[:size]
		if _, err := io.ReadFull(r.br, frame); err != nil {
			return nil, err
		}
		// A zero-length block is legal on the wire and carries no frame.
		if size == 0 {
			continue
		}
		return frame, nil
	}
}

// discardOne reads and drops one length-prefixed payload, for keepalives.
func (r *blockReader) discardOne() error {
	size, err := r.readUint32()
	if err != nil {
		return err
	}
	if size > maxBlockSize {
		return fmt.Errorf("%w: keepalive of %d octets", errBlockTooLarge, size)
	}
	_, err = io.CopyN(io.Discard, r.br, int64(size))
	return err
}

func (r *blockReader) readUint32() (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r.br, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}
