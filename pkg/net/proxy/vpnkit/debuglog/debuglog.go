// Package debuglog is the single switch for protocol-level verbose output.
//
// It exists because the alternative had already started growing: `sstp` read
// VEEPIN_SSTP_DEBUG from the environment in three places, because someone
// needed exactly this and there was nowhere to put it. One environment variable
// per protocol is not a design, it is what happens without one — the next
// protocol that needs the same thing invents VEEPIN_<ITS NAME>_DEBUG, and an
// operator debugging a tunnel has to know which spelling their protocol chose.
//
// The switch is a package variable rather than a field on each protocol's
// Config because of who sets it and who reads it. It is set once, by
// `veepin -log-level=debug`, before anything is dialled; it is read by whichever
// protocol package happens to want detail. Threading a level through seventeen
// facades' Config structs to turn on a diagnostic is more plumbing than the
// diagnostic is worth, and none of those Configs would otherwise have a field
// for it.
//
// A protocol package that takes an explicit Logger in its Config is unaffected:
// an embedder who supplied one has already said where their logs go, and this
// only decides what an *unconfigured* logger does.
package debuglog

import (
	"io"
	"os"
	"sync/atomic"
)

// enabled is atomic because it is set on the command's main goroutine before
// any dial and read from data-path goroutines afterwards. The race is benign in
// practice and the atomic costs a relaxed load; the race detector disagreeing
// with "in practice" during an interop run is not a debate worth having.
var enabled atomic.Bool

// SetEnabled turns protocol-level detail on or off. `veepin` calls it once,
// from -log-level.
func SetEnabled(on bool) { enabled.Store(on) }

// Enabled reports whether protocol-level detail was asked for.
func Enabled() bool { return enabled.Load() }

// Writer is where an unconfigured protocol logger should write: stderr when
// debug is on, and nowhere otherwise.
//
// Stderr rather than stdout, because this is diagnostic output and the tunnel's
// own status lines go to stdout — an operator piping one should not get the
// other.
func Writer() io.Writer {
	if Enabled() {
		return os.Stderr
	}
	return io.Discard
}

func init() {
	// The environment variable is still honoured, for two reasons: it is what
	// existing runbooks and the interop entrypoints pass, and it is the only
	// way to get detail out of a Go program that embeds a protocol package
	// directly rather than going through the veepin command.
	//
	// VEEPIN_SSTP_DEBUG is the historical spelling and keeps working; VEEPIN_DEBUG
	// is the one to use.
	if os.Getenv("VEEPIN_DEBUG") != "" || os.Getenv("VEEPIN_SSTP_DEBUG") != "" {
		enabled.Store(true)
	}
}
