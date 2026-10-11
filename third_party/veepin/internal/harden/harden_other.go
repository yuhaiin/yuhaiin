//go:build !linux

package harden

import "errors"

// ErrUnsupported reports that this platform has neither mlockall nor
// PR_SET_DUMPABLE reachable through x/sys/unix in the shape this package needs.
//
// It is an error rather than a silent no-op deliberately. An operator who asked
// for memory locking and did not get it should be told, not left believing a
// protection is in place -- which is the same argument doc/security.md makes for
// refusing to fake key zeroing.
var ErrUnsupported = errors.New("harden: process hardening is implemented on Linux only")

// Apply reports ErrUnsupported when anything was requested, and succeeds
// trivially when nothing was.
func Apply(o Options) (applied []string, err error) {
	if !o.Any() {
		return nil, nil
	}
	return nil, ErrUnsupported
}
