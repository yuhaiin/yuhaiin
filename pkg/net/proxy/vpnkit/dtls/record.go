package dtls

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
)

// The DTLS record layer (RFC 6347 section 4.1).
//
//	 0      1..2      3..4       5..10        11..12
//	+------+---------+---------+------------+---------+----------+
//	| type | version |  epoch  |  sequence  | length  | fragment |
//	+------+---------+---------+------------+---------+----------+
//
// The epoch counts cipher-state changes and the 48-bit sequence numbers restart
// within each one, which together let a receiver tell a record encrypted under
// the old keys from one under the new. Unlike TLS, records are independent: any
// may be lost, reordered or duplicated, so nothing may depend on their order.

var (
	errShortRecord = errors.New("dtls: truncated record")
	errReplay      = errors.New("dtls: replayed or too-old record")
)

// record is one decoded record.
type record struct {
	typ      uint8
	version  uint16
	epoch    uint16
	sequence uint64 // 48 bits
	fragment []byte
}

// parseRecord decodes the first record in buf and reports how many octets it
// used, so a datagram carrying several can be walked.
func parseRecord(buf []byte) (record, int, error) {
	if len(buf) < recordHeaderLen {
		return record{}, 0, errShortRecord
	}
	length := int(binary.BigEndian.Uint16(buf[11:13]))
	total := recordHeaderLen + length
	if len(buf) < total {
		return record{}, 0, errShortRecord
	}
	var seq uint64
	for _, b := range buf[5:11] {
		seq = seq<<8 | uint64(b)
	}
	return record{
		typ:      buf[0],
		version:  binary.BigEndian.Uint16(buf[1:3]),
		epoch:    binary.BigEndian.Uint16(buf[3:5]),
		sequence: seq,
		fragment: buf[recordHeaderLen:total],
	}, total, nil
}

// appendRecordHeader writes a record header for a payload of the given length.
func appendRecordHeader(dst []byte, typ uint8, version uint16, epoch uint16, seq uint64, length int) []byte {
	dst = append(dst, typ)
	dst = binary.BigEndian.AppendUint16(dst, version)
	dst = binary.BigEndian.AppendUint16(dst, epoch)
	dst = append(dst,
		byte(seq>>40), byte(seq>>32), byte(seq>>24),
		byte(seq>>16), byte(seq>>8), byte(seq))
	return binary.BigEndian.AppendUint16(dst, uint16(length))
}

// aeadState holds one direction's AEAD and its implicit nonce salt. An instance
// is used for exactly one direction — the read AEAD only opens, the write AEAD
// only seals — and each direction is driven by a single goroutine (Conn.Read
// under readMu, Conn.Write under writeMu). That lets the per-record nonce and
// additional-data buffers be reused across records without a lock and, crucially,
// without escaping to the heap through the cipher.AEAD interface on every packet.
type aeadState struct {
	aead cipher.AEAD
	salt []byte
	// nonce is salt (fixed) followed by the 8-octet explicit part, rewritten per
	// record. aad is the 13-octet additional data, likewise rewritten per record.
	nonce []byte
	aad   [13]byte
}

func newAEAD(key, salt []byte) (*aeadState, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("dtls: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("dtls: GCM: %w", err)
	}
	a := &aeadState{aead: gcm, salt: append([]byte(nil), salt...)}
	a.nonce = make([]byte, len(a.salt)+explicitNonceLen)
	copy(a.nonce, a.salt) // the salt prefix never changes
	return a, nil
}

// putAAD fills the reused additional-data buffer for one record.
func (a *aeadState) putAAD(typ uint8, version uint16, epoch uint16, seq uint64, length int) {
	binary.BigEndian.PutUint16(a.aad[0:2], epoch)
	putUint48(a.aad[2:8], seq)
	a.aad[8] = typ
	binary.BigEndian.PutUint16(a.aad[9:11], version)
	binary.BigEndian.PutUint16(a.aad[11:13], uint16(length))
}

// seal encrypts a record payload. The GCM nonce is the 4-octet salt from the key
// block followed by an 8-octet explicit part, which is sent in the clear ahead of
// the ciphertext; using the record's epoch and sequence for it makes the nonce
// unique without any extra state (RFC 5288).
func (a *aeadState) seal(typ uint8, version uint16, epoch uint16, seq uint64, plaintext []byte) []byte {
	// The output begins with the explicit nonce, sent in the clear, and has room
	// for the ciphertext and tag Seal appends after it — one allocation for the
	// whole record payload rather than a separate sealed buffer and a copy.
	out := make([]byte, explicitNonceLen, explicitNonceLen+len(plaintext)+a.aead.Overhead())
	binary.BigEndian.PutUint16(out[0:2], epoch)
	putUint48(out[2:8], seq)

	// The reused nonce is salt||explicit; only the explicit part changes here.
	copy(a.nonce[len(a.salt):], out[:explicitNonceLen])
	a.putAAD(typ, version, epoch, seq, len(plaintext))
	return a.aead.Seal(out, a.nonce, plaintext, a.aad[:])
}

// open decrypts a record payload in place, taking the explicit nonce from its
// front. The returned plaintext aliases ciphertext; the caller (Conn.Read /
// the handshake reader) copies or consumes it before the buffer is reused.
func (a *aeadState) open(typ uint8, version uint16, epoch uint16, seq uint64, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < explicitNonceLen+a.aead.Overhead() {
		return nil, errShortRecord
	}
	copy(a.nonce[len(a.salt):], ciphertext[:explicitNonceLen])

	body := ciphertext[explicitNonceLen:]
	// The additional data covers the plaintext length, which is the ciphertext
	// less the explicit nonce and the tag.
	a.putAAD(typ, version, epoch, seq, len(body)-a.aead.Overhead())
	plain, err := a.aead.Open(body[:0], a.nonce, body, a.aad[:])
	if err != nil {
		return nil, fmt.Errorf("dtls: record decryption failed: %w", err)
	}
	return plain, nil
}

func putUint48(dst []byte, v uint64) {
	dst[0] = byte(v >> 40)
	dst[1] = byte(v >> 32)
	dst[2] = byte(v >> 24)
	dst[3] = byte(v >> 16)
	dst[4] = byte(v >> 8)
	dst[5] = byte(v)
}

// replayWindow is the RFC 6347 section 4.1.2.6 anti-replay filter: a sliding
// bitmap of recently seen sequence numbers within an epoch. Without it a
// recorded datagram could be re-injected indefinitely, since the AEAD alone only
// proves a record was genuine once.
type replayWindow struct {
	highest uint64
	bitmap  uint64
	started bool
}

const replayWindowSize = 64

// check reports whether seq is acceptable, and records it if so.
func (w *replayWindow) check(seq uint64) error {
	if !w.started {
		w.started = true
		w.highest = seq
		w.bitmap = 1
		return nil
	}
	switch {
	case seq > w.highest:
		shift := seq - w.highest
		if shift >= replayWindowSize {
			w.bitmap = 1
		} else {
			w.bitmap = w.bitmap<<shift | 1
		}
		w.highest = seq
		return nil
	default:
		back := w.highest - seq
		if back >= replayWindowSize {
			return errReplay
		}
		mask := uint64(1) << back
		if w.bitmap&mask != 0 {
			return errReplay
		}
		w.bitmap |= mask
		return nil
	}
}
