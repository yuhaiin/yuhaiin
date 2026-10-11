package tlswrap

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Mode is the control-channel protection a connection uses.
type Mode int

const (
	// ModeNone is the plain control channel: no per-packet HMAC or encryption.
	ModeNone Mode = iota
	// ModeAuth is --tls-auth: an HMAC over every control packet.
	ModeAuth
	// ModeCrypt is --tls-crypt: authenticated encryption of every control packet.
	ModeCrypt
)

// Wrapper adds and removes a control channel's static-key protection. Wrap is
// called on the pump goroutine before sending a marshalled control packet;
// Unwrap is called on the same goroutine for each inbound control datagram. A
// nil Wrapper means the plain profile.
type Wrapper interface {
	// Wrap protects a marshalled control packet (opcode | session_id | body),
	// returning the datagram to send.
	Wrap(pkt []byte) ([]byte, error)
	// Unwrap checks and strips protection from an inbound datagram, returning the
	// plain control packet (opcode | session_id | body) for the codec. It returns
	// an error for a packet that fails authentication or is a replay; the caller
	// drops it.
	Unwrap(datagram []byte) ([]byte, error)
}

// Field offsets shared by both wrappings: the opcode and session ID lead every
// control packet in the clear, so the muxer can still demux by opcode and the
// codec can read the session ID.
const (
	opcodeLen = 1
	sidLen    = 8
	headerLen = opcodeLen + sidLen // authenticated, never encrypted
	pidLen    = 4                  // replay packet ID
	timeLen   = 4                  // net_time, seconds since the epoch
	replayLen = pidLen + timeLen   // OpenVPN's "long form" packet ID
)

var (
	// ErrAuth reports a control packet whose HMAC did not verify: a forgery, or a
	// static key that does not match the server's.
	ErrAuth = errors.New("tlswrap: control packet authentication failed")
	// ErrReplay reports a control packet whose replay ID was already seen.
	ErrReplay = errors.New("tlswrap: replayed control packet")
	// ErrShort reports a datagram too small to hold the wrapping's fixed fields.
	ErrShort = errors.New("tlswrap: control packet too short")
	// ErrDigest reports an unsupported --auth digest.
	ErrDigest = errors.New("tlswrap: unsupported auth digest")
)

// Digest names the HMAC hash a --tls-auth (or CBC data channel) uses. OpenVPN's
// default is SHA1; modern configs commonly use SHA256.
type Digest struct {
	New  func() hash.Hash
	Size int
}

// ParseDigest maps an OpenVPN --auth name to a Digest. Only the two common
// choices are implemented.
func ParseDigest(name string) (Digest, error) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "", "SHA1", "SHA-1":
		return Digest{New: sha1.New, Size: sha1.Size}, nil
	case "SHA256", "SHA-256":
		return Digest{New: sha256.New, Size: sha256.Size}, nil
	default:
		return Digest{}, ErrDigest
	}
}

// counter hands out ascending replay packet IDs, starting at 1 (OpenVPN numbers
// control packet IDs from 1). It is atomic so Wrap needs no lock.
type counter struct{ n atomic.Uint32 }

func (c *counter) next() uint32 { return c.n.Add(1) }

// replayWindow is a 64-packet backtrack window over the 32-bit replay ID: it
// rejects a duplicate or an ID older than the window, mirroring the data
// channel's. The control channel's own reliability layer dedupes messages by
// their message ID; this guards the wrapping's separate packet ID (which also
// covers pure ACKs the reliability layer does not renumber).
type replayWindow struct {
	mu      sync.Mutex
	highest uint32
	bitmap  uint64
	started bool
}

func (w *replayWindow) accept(id uint32) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.started {
		w.started = true
		w.highest = id
		w.bitmap = 1
		return true
	}
	if id > w.highest {
		shift := id - w.highest
		if shift >= 64 {
			w.bitmap = 0
		} else {
			w.bitmap <<= shift
		}
		w.bitmap |= 1
		w.highest = id
		return true
	}
	offset := w.highest - id
	if offset >= 64 {
		return false
	}
	mask := uint64(1) << offset
	if w.bitmap&mask != 0 {
		return false
	}
	w.bitmap |= mask
	return true
}

// authWrapper implements --tls-auth: an HMAC over the whole control packet plus
// a replay packet ID and timestamp.
type authWrapper struct {
	digest   Digest
	sendKey  []byte
	recvKey  []byte
	sendID   counter
	recvSeen replayWindow
}

// NewAuth builds a --tls-auth wrapper from a static key, its direction, and the
// --auth digest.
func NewAuth(key *StaticKey, dir Direction, digest Digest) Wrapper {
	return &authWrapper{
		digest:  digest,
		sendKey: key.hmacKey(dir.outSlot(), digest.Size),
		recvKey: key.hmacKey(dir.inSlot(), digest.Size),
	}
}

// Wrap produces: opcode | session_id | HMAC | packet_id | net_time | body,
// where the HMAC covers packet_id | net_time | opcode | session_id | body.
func (w *authWrapper) Wrap(pkt []byte) ([]byte, error) {
	if len(pkt) < headerLen {
		return nil, ErrShort
	}
	header := pkt[:headerLen]
	body := pkt[headerLen:]

	id := w.sendID.next()
	now := uint32(time.Now().Unix())

	var replay [replayLen]byte
	binary.BigEndian.PutUint32(replay[:pidLen], id)
	binary.BigEndian.PutUint32(replay[pidLen:], now)

	mac := hmac.New(w.digest.New, w.sendKey)
	mac.Write(replay[:])
	mac.Write(header)
	mac.Write(body)
	tag := mac.Sum(nil)

	out := make([]byte, 0, headerLen+w.digest.Size+replayLen+len(body))
	out = append(out, header...)
	out = append(out, tag...)
	out = append(out, replay[:]...)
	out = append(out, body...)
	return out, nil
}

// Unwrap verifies the HMAC and strips the tls-auth fields, returning
// opcode | session_id | body.
func (w *authWrapper) Unwrap(dg []byte) ([]byte, error) {
	fixed := headerLen + w.digest.Size + replayLen
	if len(dg) < fixed {
		return nil, ErrShort
	}
	header := dg[:headerLen]
	tag := dg[headerLen : headerLen+w.digest.Size]
	replay := dg[headerLen+w.digest.Size : fixed]
	body := dg[fixed:]

	mac := hmac.New(w.digest.New, w.recvKey)
	mac.Write(replay)
	mac.Write(header)
	mac.Write(body)
	if !hmac.Equal(tag, mac.Sum(nil)) {
		return nil, ErrAuth
	}
	if !w.recvSeen.accept(binary.BigEndian.Uint32(replay[:pidLen])) {
		return nil, ErrReplay
	}

	out := make([]byte, 0, headerLen+len(body))
	out = append(out, header...)
	out = append(out, body...)
	return out, nil
}
