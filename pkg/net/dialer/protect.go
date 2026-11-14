package dialer

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Socket Protection keeps sockets this process opens out of its own TUN. It is
// separate from Egress Selection (which interface a socket leaves through):
//
//   - Linux: SO_MARK, which the System Network policy rule excludes from the
//     TUN table. The kernel then routes each packet by destination, so
//     protected sockets are not bound to an interface.
//   - Android: VpnService.protect(fd).
//   - macOS and Windows have no routing mark; there a socket is protected by
//     binding it to an egress interface other than the TUN (IP_BOUND_IF /
//     IP_UNICAST_IF), see egress.go.

// ErrUnprotected is returned when a socket could not be protected and no safe
// alternative exists, instead of letting it loop into the TUN.
var ErrUnprotected = errors.New("outbound socket protection failed")

// SocketProtector applies a platform protection to a new socket.
type SocketProtector struct {
	// Method names the mechanism, for status ("SO_MARK", "VpnService.protect").
	Method string
	// Mark is the routing mark, when the method uses one.
	Mark    uint32
	Protect func(fd int32) error
}

type protectionState struct {
	mu        sync.Mutex
	failures  atomic.Uint64
	successes atomic.Uint64
	lastError string
	lastAt    time.Time
}

var (
	protector  atomic.Pointer[SocketProtector]
	protection protectionState
	// unavailable explains why the platform protector could not be installed.
	unavailable atomic.Pointer[ProtectionUnavailable]
)

// ProtectionUnavailable records a protector that could not be installed.
type ProtectionUnavailable struct {
	Method string
	Mark   uint32
	Reason string
}

// SetProtectionUnavailable records why the platform protector is missing.
func SetProtectionUnavailable(u *ProtectionUnavailable) { unavailable.Store(u) }

// SetSocketProtector installs (or with nil, removes) the platform protector.
// It resets the recorded protection results.
func SetSocketProtector(p *SocketProtector) {
	protector.Store(p)
	protection.failures.Store(0)
	protection.successes.Store(0)
	protection.mu.Lock()
	protection.lastError = ""
	protection.lastAt = time.Time{}
	protection.mu.Unlock()
}

// CurrentSocketProtector returns the installed protector, or nil.
func CurrentSocketProtector() *SocketProtector { return protector.Load() }

// protectSocket applies the installed protector. It reports whether the
// socket is protected; a nil protector is not an error (the platform protects
// by egress binding, or has no own TUN).
func protectSocket(fd uintptr) (bool, error) {
	p := protector.Load()
	if p == nil || p.Protect == nil {
		return false, nil
	}
	if err := p.Protect(int32(fd)); err != nil {
		protection.failures.Add(1)
		protection.mu.Lock()
		protection.lastError = err.Error()
		protection.lastAt = time.Now()
		protection.mu.Unlock()
		return false, fmt.Errorf("%w: %s: %w", ErrUnprotected, p.Method, err)
	}
	protection.successes.Add(1)
	return true, nil
}

// ProtectionReport summarizes protection results since the protector was set.
type ProtectionReport struct {
	Method      string
	Mark        uint32
	Installed   bool
	Successes   uint64
	Failures    uint64
	LastError   string
	LastErrorAt time.Time
	// Unavailable is set when the platform protector could not be installed.
	Unavailable string
}

func Protection() ProtectionReport {
	r := ProtectionReport{Successes: protection.successes.Load(), Failures: protection.failures.Load()}
	if p := protector.Load(); p != nil {
		r.Installed = true
		r.Method = p.Method
		r.Mark = p.Mark
	} else if u := unavailable.Load(); u != nil {
		r.Method = u.Method
		r.Mark = u.Mark
		r.Unavailable = u.Reason
	}
	protection.mu.Lock()
	r.LastError = protection.lastError
	r.LastErrorAt = protection.lastAt
	protection.mu.Unlock()
	return r
}

// markProtects reports whether the installed protector is a routing mark
// that has not failed: then the kernel keeps protected sockets out of the TUN
// on its own and Egress Selection can leave them unbound.
func markProtects() bool {
	p := protector.Load()
	return p != nil && p.Mark != 0 && protection.failures.Load() == 0
}

// ProtectRawSocket protects a socket created outside the dialer (ICMP). A
// failure is returned only while our TUN is up, where the socket could loop.
func ProtectRawSocket(fd uintptr) error {
	_, err := protectSocket(fd)
	if err != nil && ownTunActive() {
		return err
	}
	return nil
}
