package keys

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// NewServerKeySource generates a server's random key material. The server sends
// only the two randoms — its pre-master stays zero and is unused, since the
// master secret is derived from the client's pre-master.
func NewServerKeySource() (*KeySource, error) {
	ks := &KeySource{}
	for _, b := range [][]byte{ks.Random1[:], ks.Random2[:]} {
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("keys: random: %w", err)
		}
	}
	return ks, nil
}

// MarshalServer encodes a server key-method-2 message: the leading zero word, the
// method byte, the server's two randoms (no pre-master), and the OCC options
// string. Unlike a client message it carries no username, password or peer-info.
func (ks *KeySource) MarshalServer(options string) []byte {
	var b []byte
	b = append(b, 0, 0, 0, 0) // leading uint32(0)
	b = append(b, keyMethod2)
	b = append(b, ks.Random1[:]...)
	b = append(b, ks.Random2[:]...)
	b = appendString(b, options)
	return b
}

// readStringField reads an OpenVPN write_string field, tolerating a zero-length
// field. OpenVPN encodes an empty or NULL string (e.g. username/password when no
// auth-user-pass is set) as a uint16 length of 0 with no trailing null, whereas a
// non-empty string's length includes its trailing null. The strict readString
// used for the required server options rejects the zero case; here it is valid.
func readStringField(b []byte, off int) (string, int, error) {
	if off+2 > len(b) {
		return "", off, ErrShortMessage
	}
	n := int(binary.BigEndian.Uint16(b[off:]))
	off += 2
	if n == 0 {
		return "", off, nil
	}
	if off+n > len(b) {
		return "", off, ErrShortMessage
	}
	return string(b[off : off+n-1]), off + n, nil
}

// ClientHello is the decoded content of a client key-method-2 message.
type ClientHello struct {
	KeySource KeySource
	Options   string
	Username  string
	Password  string
	PeerInfo  string
}

// ParseClient decodes a client key-method-2 message: the leading zero word, the
// method byte, the client's pre-master and two randoms, the OCC options string,
// and the optional username, password and peer-info. The trailing credential and
// peer-info fields default to empty when a minimal client omits them.
func ParseClient(b []byte) (*ClientHello, error) {
	if len(b) < 5+preMasterLen+2*randomLen {
		return nil, ErrShortMessage
	}
	if b[4] != keyMethod2 {
		return nil, ErrBadKeyMethod
	}
	off := 5
	h := &ClientHello{}
	off += copy(h.KeySource.PreMaster[:], b[off:off+preMasterLen])
	off += copy(h.KeySource.Random1[:], b[off:off+randomLen])
	off += copy(h.KeySource.Random2[:], b[off:off+randomLen])

	var err error
	if h.Options, off, err = readStringField(b, off); err != nil {
		return nil, err
	}
	if off >= len(b) {
		return h, nil
	}
	if h.Username, off, err = readStringField(b, off); err != nil {
		return nil, err
	}
	if off >= len(b) {
		return h, nil
	}
	if h.Password, off, err = readStringField(b, off); err != nil {
		return nil, err
	}
	// peer_info is length-prefixed but not null-terminated (OpenVPN reads exactly
	// the prefixed length).
	if off+2 <= len(b) {
		n := int(binary.BigEndian.Uint16(b[off:]))
		off += 2
		if n > 0 && off+n <= len(b) {
			h.PeerInfo = string(b[off : off+n])
		}
	}
	return h, nil
}
