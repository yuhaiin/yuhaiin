package ike

// The IKEv2 cookie exchange (RFC 7296 §2.6).
//
// IKE_SA_INIT is the most expensive thing an unauthenticated peer can ask a
// responder to do: a Diffie-Hellman computation, plus state held until the
// exchange completes or times out. An initiator address is trivially spoofable
// over UDP, so without a defence a responder performs that work for traffic that
// never had a real peer behind it.
//
// The cookie is the standard answer and it is better than a rate limit, because
// it costs the responder nothing. Under load the responder replies with a cookie
// derived from the initiator's own SPI, nonce and address, and refuses to do any
// further work until that exact cookie comes back. A spoofing attacker never
// sees the reply, so it can never return the cookie; a real initiator returns it
// on its next message and proceeds.
//
// The construction is deliberately stateless — nothing about an outstanding
// cookie is remembered. Storing them would recreate the very allocation the
// mechanism exists to avoid, which is the mistake RFC 7296 §2.6 explicitly warns
// against. The recommended form is used:
//
//	Cookie = <VersionIDOfSecret> | Hash(Ni | IPi | SPIi | <secret>)
//
// The secret is rotated periodically, and one previous secret is kept valid so a
// cookie in flight across a rotation is not spuriously rejected.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/xen0bit/veepin/internal/cryptoutil"
)

const (
	// cookieSecretLen is the size of the rotating secret.
	cookieSecretLen = 32
	// cookieRotate is how often the secret is replaced. A cookie is usable for
	// up to twice this, since the previous secret stays valid.
	cookieRotate = 2 * time.Minute
	// cookieThreshold is how many half-open exchanges must be in flight before
	// the responder starts demanding cookies. Below it, handshakes complete in
	// the usual two round trips; above it, every initiator pays one extra
	// round trip and spoofed traffic stops costing anything at all.
	cookieThreshold = 32
	// cookieLen is one version octet plus a truncated hash. RFC 7296 leaves the
	// size to the responder; this is comfortably beyond guessing while keeping
	// the notify small.
	cookieLen = 1 + 16
)

// cookieJar issues and checks cookies. It holds no per-initiator state.
type cookieJar struct {
	mu      sync.Mutex
	current [cookieSecretLen]byte
	prev    [cookieSecretLen]byte
	version uint8
	rotated time.Time
	// now is the clock, for tests.
	now func() time.Time
}

func newCookieJar() *cookieJar {
	j := &cookieJar{now: time.Now}
	j.rotate()
	return j
}

// rotate installs a fresh secret, retaining the previous one.
func (j *cookieJar) rotate() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.prev = j.current
	if _, err := rand.Read(j.current[:]); err != nil {
		// A responder that cannot generate a secret cannot issue cookies. The
		// caller treats an empty cookie as "do not require one", which degrades
		// to the previous behaviour rather than refusing all traffic.
		return
	}
	j.version++
	j.rotated = j.now()
}

// maybeRotate replaces the secret if it has aged out.
func (j *cookieJar) maybeRotate() {
	j.mu.Lock()
	stale := j.now().Sub(j.rotated) >= cookieRotate
	j.mu.Unlock()
	if stale {
		j.rotate()
	}
}

// issue computes the cookie for an initiator, binding it to the values that
// identify this attempt. Binding the address is what makes a spoofed source
// useless: a cookie issued to a forged address is only valid for that address,
// and the attacker never receives it anyway.
func (j *cookieJar) issue(initiatorSPI uint64, nonce []byte, remote *net.UDPAddr) []byte {
	j.maybeRotate()

	j.mu.Lock()
	secret, version := j.current, j.version
	j.mu.Unlock()

	return cookieWith(secret, version, initiatorSPI, nonce, remote)
}

// valid reports whether a returned cookie is one this responder issued for these
// values, under either the current or the previous secret.
func (j *cookieJar) valid(got []byte, initiatorSPI uint64, nonce []byte, remote *net.UDPAddr) bool {
	if len(got) != cookieLen {
		return false
	}

	j.mu.Lock()
	current, prev, version := j.current, j.prev, j.version
	j.mu.Unlock()

	// The version octet says which secret to check, so a rotation does not
	// invalidate a cookie already in flight.
	switch got[0] {
	case version:
		return cryptoutil.SecretEqual(got, cookieWith(current, version, initiatorSPI, nonce, remote))
	case version - 1:
		return cryptoutil.SecretEqual(got, cookieWith(prev, version-1, initiatorSPI, nonce, remote))
	default:
		return false
	}
}

// cookieWith is the construction itself, factored out so issue and valid cannot
// drift apart.
func cookieWith(secret [cookieSecretLen]byte, version uint8, initiatorSPI uint64, nonce []byte, remote *net.UDPAddr) []byte {
	mac := hmac.New(sha256.New, secret[:])

	var spi [8]byte
	binary.BigEndian.PutUint64(spi[:], initiatorSPI)
	mac.Write(nonce)
	if remote != nil {
		mac.Write(remote.IP)
		var port [2]byte
		binary.BigEndian.PutUint16(port[:], uint16(remote.Port))
		mac.Write(port[:])
	}
	mac.Write(spi[:])

	out := make([]byte, 0, cookieLen)
	out = append(out, version)
	return append(out, mac.Sum(nil)[:cookieLen-1]...)
}
