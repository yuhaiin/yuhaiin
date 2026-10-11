package noise

// Cookies: WireGuard's answer to a handshake flood (protocol paper §5.3, §5.4.7).
//
// A responder pays two Diffie-Hellman operations for every initiation before it
// knows anything about the sender, and the sender's address is spoofable. mac1
// proves only that the sender knows the responder's public key. Under load the
// responder therefore stops answering initiations that lack a valid mac2 and
// sends a cookie reply instead: an encrypted token bound to the sender's
// address, which only a sender that can receive at that address will ever see.
// It retries with mac2 computed under that token, and the responder, now sure
// of the address, can rate-limit by it meaningfully.
//
//	initiator                                 responder (under load)
//	    | -- initiation (mac1, mac2 = 0) ------->  |  mac1 ok, mac2 bad:
//	    | <-- cookie reply (XAEAD(cookie)) ------  |  no DH, no state kept
//	    |       ...REKEY_TIMEOUT...                |
//	    | -- initiation (mac1, mac2 = MAC(c)) --->  |  mac2 ok: proceed
//	    | <-- response ----------------------------  |
//
// The cookie is never stored by the responder. It is recomputed from a secret
// that rotates every two minutes and the source address the datagram arrived
// from, so answering a flood costs one keyed hash and one AEAD seal per
// datagram, and no memory at all.
//
// The steps below are the paper's, each quoted at the line implementing it.

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/xen0bit/veepin/internal/cryptoutil"
	"github.com/xen0bit/veepin/internal/wireguard/wire"
)

const labelCookie = "cookie--"

// CookieRefreshTime is both how long a responder's cookie secret lives and how
// long an initiator may use a cookie it was given (the paper's 120 seconds,
// wireguard-go's CookieRefreshTime). Past it, the responder's secret has
// changed and the cookie would compute a mac2 nobody accepts.
const CookieRefreshTime = 120 * time.Second

var (
	// ErrCookieReply reports a cookie reply that is not for this handshake or
	// does not decrypt: a stray, a forgery, or one for an initiation we did not
	// send. It is dropped; the handshake carries on as though it never came.
	ErrCookieReply = errors.New("noise: cookie reply does not authenticate")
)

// Cookie is a responder's token, as an initiator holds it.
type Cookie [wire.CookieSize]byte

// CookieChecker is the responder's half: it verifies mac1 and mac2 on inbound
// initiations and builds cookie replies. One serves a whole server. It is safe
// for concurrent use.
type CookieChecker struct {
	mac1Key key // HASH(LABEL_MAC1 || responder.static_public)
	encKey  key // HASH(LABEL_COOKIE || responder.static_public)

	// typeInitiation is AmneziaWG's H1, which both MACs are computed over in
	// place of the stock type word; see Config.
	typeInitiation uint32

	// Now is the clock, for tests. Nil means time.Now.
	Now func() time.Time

	mu       sync.Mutex
	secret   [32]byte
	secretAt time.Time
}

// NewCookieChecker builds the checker for the responder whose static private
// key is localStatic. typeInitiation is AmneziaWG's H1, or zero for stock.
func NewCookieChecker(localStatic [KeySize]byte, typeInitiation uint32) (*CookieChecker, error) {
	pub, err := PublicKey(localStatic)
	if err != nil {
		return nil, err
	}
	return &CookieChecker{
		mac1Key:        hashOf([]byte(labelMAC1), pub[:]),
		encKey:         hashOf([]byte(labelCookie), pub[:]),
		typeInitiation: typeInitiation,
	}, nil
}

func (c *CookieChecker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// CheckMAC1 reports whether an initiation's mac1 authenticates to this
// responder's static key. It is the cheap first gate, before anything else is
// spent on the datagram.
func (c *CookieChecker) CheckMAC1(msg []byte) bool {
	over1, _, ok := wire.MACRegions(msg)
	if !ok || len(msg) != wire.SizeHandshakeInitiation {
		return false
	}
	want := mac128(c.mac1Key[:], macOver(over1, c.typeInitiation))
	return subtle.ConstantTimeCompare(want[:], msg[len(over1):len(over1)+wire.MACSize]) == 1
}

// CheckMAC2 reports whether an initiation carries a valid mac2 for the address
// it arrived from: that is, whether its sender has received a cookie reply sent
// to that address within the secret's lifetime.
//
// A secret past its lifetime validates nothing. The cookie made from it is one
// the initiator has stopped using anyway, and accepting it would stretch a
// cookie's validity past what the protocol promises.
func (c *CookieChecker) CheckMAC2(msg []byte, src netip.AddrPort) bool {
	_, over2, ok := wire.MACRegions(msg)
	if !ok || len(msg) != wire.SizeHandshakeInitiation {
		return false
	}
	c.mu.Lock()
	fresh := !c.secretAt.IsZero() && c.now().Sub(c.secretAt) <= CookieRefreshTime
	cookie := c.cookieFor(src)
	c.mu.Unlock()
	if !fresh {
		return false
	}
	// msg.mac2 = MAC(cookie, msg[0:offsetof(msg.mac2)])
	want := mac128(cookie[:], macOver(over2, c.typeInitiation))
	return subtle.ConstantTimeCompare(want[:], msg[len(over2):len(over2)+wire.MACSize]) == 1
}

// CookieReply builds message type 3 answering the initiation msg, which must
// already have passed CheckMAC1, for a sender at src. The reply carries the
// stock type word; an AmneziaWG server substitutes H3 on the way out as it does
// for every message.
func (c *CookieChecker) CookieReply(msg []byte, src netip.AddrPort) ([]byte, error) {
	if len(msg) != wire.SizeHandshakeInitiation {
		return nil, wire.ErrMalformed
	}
	over1, _, _ := wire.MACRegions(msg)
	mac1 := msg[len(over1) : len(over1)+wire.MACSize]

	c.mu.Lock()
	// The secret is regenerated lazily, when a reply needs it and it has aged
	// out -- the paper's "changes every two minutes", without a timer.
	if c.secretAt.IsZero() || c.now().Sub(c.secretAt) > CookieRefreshTime {
		if _, err := rand.Read(c.secret[:]); err != nil {
			c.mu.Unlock()
			return nil, err
		}
		c.secretAt = c.now()
	}
	// τ = MAC(Rm, Am): the secret, keyed over the sender's address.
	cookie := c.cookieFor(src)
	c.mu.Unlock()

	reply := wire.CookieReply{Receiver: binary.LittleEndian.Uint32(msg[4:8])}
	if _, err := rand.Read(reply.Nonce[:]); err != nil {
		return nil, err
	}
	// msg.encrypted_cookie = XAEAD(HASH(LABEL_COOKIE || responder.static_public),
	//                              msg.nonce, τ, mac1-of-the-message-being-answered)
	aead, err := cryptoutil.NewXChaCha20Poly1305(c.encKey[:])
	if err != nil {
		return nil, err
	}
	aead.Seal(reply.Cookie[:0], reply.Nonce[:], cookie[:], mac1)
	return reply.Marshal(make([]byte, wire.SizeCookieReply))
}

// cookieFor computes τ = MAC(Rm, Am) for the current secret. Called with mu
// held.
//
// Am is the address and port, the paper's "IP address and UDP source port".
// Only this responder ever computes it -- the initiator echoes τ without
// interpreting it -- so its encoding is a local choice: the address in its own
// family (an IPv4-mapped address unmapped, so one client is one cookie however
// the socket reports it) followed by the port, big-endian.
func (c *CookieChecker) cookieFor(src netip.AddrPort) Cookie {
	var am [18]byte
	a := src.Addr().Unmap()
	n := copy(am[:], a.AsSlice())
	binary.BigEndian.PutUint16(am[n:], src.Port())
	return Cookie(mac128(c.secret[:], am[:n+2]))
}

// SetCookie gives the initiator a cookie to compute mac2 with. It must be called
// before Initiation; a zero Cookie (the default) leaves mac2 zero, which is what
// an initiator that has not been asked for one sends.
func (i *Initiator) SetCookie(c Cookie) { i.cookie = c }

// ConsumeCookieReply opens a cookie reply to this initiator's initiation,
// returning the cookie it carries for the caller to keep (CookieRefreshTime)
// and set on later initiations.
//
// The reply is authenticated against the mac1 we sent, which is what makes a
// forged one worthless: only a sender that saw our initiation can bind a cookie
// to it, and only one holding the responder's public key can encrypt it.
func (i *Initiator) ConsumeCookieReply(pkt []byte) (Cookie, error) {
	if !i.sent {
		return Cookie{}, ErrCookieReply
	}
	msg, err := wire.ParseCookieReply(pkt)
	if err != nil {
		return Cookie{}, err
	}
	if msg.Receiver != i.localIdx {
		return Cookie{}, ErrCookieReply
	}
	aead, err := cryptoutil.NewXChaCha20Poly1305(i.cookieKey[:])
	if err != nil {
		return Cookie{}, err
	}
	var c Cookie
	if _, err := aead.Open(c[:0], msg.Nonce[:], msg.Cookie[:], i.lastMAC1[:]); err != nil {
		return Cookie{}, ErrCookieReply
	}
	return c, nil
}
