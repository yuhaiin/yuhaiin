package wireguard

// Both ends of WireGuard's cookie exchange, as this package uses them. The
// cryptography is internal/wireguard/noise's (cookie.go); what lives here is the
// state around it: the cookie a client is holding, and whether a server
// considers itself under load.
//
// Without either, a client facing a loaded wireguard-go server -- which answers
// every initiation lacking a valid mac2 with a cookie reply -- dropped the reply
// as a parse failure and retried without one, forever; and a veepin server had
// no answer to a spoofed-source flood except a per-source rate limit that a
// spoofed source walks straight past.

import (
	"sync"
	"time"

	"github.com/xen0bit/veepin/internal/wireguard/noise"
)

// cookieJar is the cookie a client was last given, and when. A cookie is good
// for noise.CookieRefreshTime, after which the server's secret has rotated and
// a mac2 computed from it would be refused anyway, so a stale one is simply not
// used.
//
// It is shared by the initial handshake and every rekey, under a lock because
// readLoop delivers cookie replies on its own goroutine.
type cookieJar struct {
	mu     sync.Mutex
	cookie noise.Cookie
	at     time.Time
}

// keep records a cookie the server just gave us.
func (j *cookieJar) keep(c noise.Cookie) {
	j.mu.Lock()
	j.cookie, j.at = c, time.Now()
	j.mu.Unlock()
}

// apply sets the held cookie on a fresh initiator, if there is one and it is
// still fresh.
func (j *cookieJar) apply(i *noise.Initiator) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !j.at.IsZero() && time.Since(j.at) < noise.CookieRefreshTime {
		i.SetCookie(j.cookie)
	}
}

// DefaultCookieThreshold is how many handshake initiations a second a server
// takes before it considers itself under load and starts answering ones
// without a valid mac2 with a cookie reply.
//
// The number wireguard-go uses is a queue depth, not a rate -- it is under load
// once 128 initiations are waiting to be processed -- and this server handles
// initiations on its read loop rather than queueing them, so there is no queue
// to measure. The same 128, as a rate, is an order of magnitude above what a
// thousand peers rekeying every two minutes produce (about eight a second), and
// an order below what one core can answer (several thousand), which is the
// span the threshold has to sit in.
const DefaultCookieThreshold = 128

// underLoadFor is how long a server stays under load after the rate last
// exceeded the threshold: wireguard-go's UnderLoadAfterTime. Without it the
// state would flap every second under a flood that pauses for breath.
const underLoadFor = time.Second

// handshakeLoad decides when a server is under load: more than threshold
// initiations (that passed mac1) in the current one-second window, or within
// underLoadFor of the last time there were. A negative threshold means always.
//
// It is owned by the server's read loop, the one goroutine that handles
// initiations, so it carries no lock.
type handshakeLoad struct {
	threshold int
	now       func() time.Time

	windowStart time.Time
	count       int
	until       time.Time
	loaded      bool // the state at the last observation, to log the edge once
}

// observe counts one initiation and reports whether the server is under load,
// and whether that is a change since the last call -- so the caller can say so
// once per episode rather than once per datagram of a flood.
func (l *handshakeLoad) observe() (underLoad, changed bool) {
	if l.threshold < 0 {
		return true, false
	}
	now := l.now()
	if now.Sub(l.windowStart) >= time.Second {
		l.windowStart, l.count = now, 0
	}
	l.count++
	if l.count > l.threshold {
		l.until = now.Add(underLoadFor)
	}
	underLoad = now.Before(l.until)
	changed = underLoad != l.loaded
	l.loaded = underLoad
	return underLoad, changed
}
