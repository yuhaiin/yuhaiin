// Package vlog is this tree's logger: log/slog underneath, with the
// Printf-shaped calls every data path already makes, and — the point of it — a
// level chosen at the call site rather than for the stream as a whole.
//
// # Why a type at all, rather than *slog.Logger directly
//
// Before this, every package held a *log.Logger and wrote one Printf per line.
// *log.Logger has no notion of level, so `-log-level warn` could only mean
// "send the whole stream to io.Discard": a protocol reporting a genuine problem
// was suppressed along with the chatter, and the flag's own documentation had
// to say so. Making warn mean something *within* the stream is what this is for.
//
// Going straight to *slog.Logger would have meant rewriting all ~480 call sites,
// because slog takes a message and attributes where this tree takes a format
// string and arguments -- `Info(fmt.Sprintf(...))` at every one of them, which
// is worse code than the helper below and a far larger diff to read. Wrapping
// costs one type and keeps every existing line untouched, so the diff that
// changes *behaviour* is only the lines that changed level, which is the diff a
// reviewer actually wants to see.
//
// Public API surfaces *slog.Logger, not this type: a caller outside the tree
// hands in a standard-library logger and this wraps it (From). The wrapper is an
// internal convenience, not something a facade's user has to learn.
//
// # The one rule about levels
//
// **Never reclassify a line downward.** Moving a line from Info to Warn or Error
// keeps it visible at the default level and makes it survive `-log-level warn`;
// moving one to Debug hides it from everybody who has not asked for debug. There
// are thirty-two interop cells asserting substrings of veepin's own log output
// and a management panel that shows the stream as free text, and neither of them
// would fail loudly — they would fail as a line that stopped appearing.
package vlog

import (
	"context"
	"fmt"
	"io"
	"log/slog"
)

// Logger writes Printf-shaped lines to a slog.Handler at a level the call site
// chooses. The zero value is not usable; a nil *Logger is, and discards.
type Logger struct {
	s *slog.Logger
	// prefix goes in front of every message. Most of this tree needs none --
	// its messages start with their own package name by convention -- but the
	// NetworkManager service's lines are "ready" and "exiting", and their whole
	// identity in the journal is the prefix.
	prefix string
}

// New wraps an *slog.Logger. A nil argument yields a discarding Logger, which is
// what every package's "no logger configured" branch wants.
func New(s *slog.Logger) *Logger {
	if s == nil {
		return Discard()
	}
	return &Logger{s: s}
}

// Prefixed returns a copy of l that writes prefix in front of every message.
func (l *Logger) Prefixed(prefix string) *Logger {
	if l == nil {
		return nil
	}
	out := *l
	out.prefix = prefix
	return &out
}

// From is New, named for the direction it is used in: a facade takes an
// *slog.Logger from its Config and turns it into the logger the implementation
// holds.
func From(s *slog.Logger) *Logger { return New(s) }

// Discard returns a Logger that writes nothing. It is a real Logger rather than
// nil so that callers who want to be explicit can be.
func Discard() *Logger {
	return &Logger{s: slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
		Level: slog.LevelError + 1,
	}))}
}

// Slog returns the underlying logger, for the rare caller that wants attributes.
func (l *Logger) Slog() *slog.Logger {
	if l == nil {
		return slog.New(discardHandler{})
	}
	return l.s
}

// Enabled reports whether a line at this level would be written. Call it before
// building an expensive message: the formatting below is skipped when the level
// is off, but only the arguments' evaluation is the caller's to avoid.
func (l *Logger) Enabled(level slog.Level) bool {
	if l == nil || l.s == nil {
		return false
	}
	return l.s.Enabled(context.Background(), level)
}

// Printf writes one line at Info. It is the direct replacement for
// (*log.Logger).Printf and the reason every existing call site compiles
// unchanged.
func (l *Logger) Printf(format string, args ...any) { l.logf(slog.LevelInfo, format, args...) }

// Debugf writes one line at Debug: detail an operator has to ask for.
func (l *Logger) Debugf(format string, args ...any) { l.logf(slog.LevelDebug, format, args...) }

// Warnf writes one line at Warn: something went wrong that the tunnel survived.
func (l *Logger) Warnf(format string, args ...any) { l.logf(slog.LevelWarn, format, args...) }

// Errorf writes one line at Error: something went wrong that it did not.
//
// It does not exit and does not return an error — a fatal condition travels back
// to the caller as a Go error and is printed by the command, never here.
func (l *Logger) Errorf(format string, args ...any) { l.logf(slog.LevelError, format, args...) }

// logf formats and emits. The Enabled check comes first so a suppressed line
// costs no formatting: the drop paths on every data path log through this, and a
// flood of bad packets must not start allocating because somebody left the
// logger set.
func (l *Logger) logf(level slog.Level, format string, args ...any) {
	if l == nil || l.s == nil {
		return
	}
	ctx := context.Background()
	if !l.s.Enabled(ctx, level) {
		return
	}
	l.s.Log(ctx, level, l.prefix+fmt.Sprintf(format, args...))
}

// discardHandler is what Slog returns for a nil Logger, so a caller reaching
// through gets something safe rather than a panic.
type discardHandler struct{}

func (discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (h discardHandler) WithAttrs([]slog.Attr) slog.Handler      { return h }
func (h discardHandler) WithGroup(string) slog.Handler           { return h }

// Text is the logger the commands and tests want when they just need lines on a
// writer: the customary timestamped format, everything at Info and above.
//
// It exists so that the fifty-odd places that used to say
// `log.New(w, "", log.LstdFlags|log.Lmicroseconds)` have one thing to say
// instead, and so that they all agree on the format the panel and the interop
// cells read.
func Text(w io.Writer) *Logger { return New(SlogText(w)) }

// SlogText is Text for a caller that needs the standard-library type — a
// facade's public Logger field, which is *slog.Logger so that nobody outside
// this tree has to learn the wrapper.
func SlogText(w io.Writer) *slog.Logger {
	return slog.New(NewTextHandler(w, slog.LevelInfo))
}

// Plain is Text without the timestamp — the shape log.New(w, "", 0) wrote. Tests
// that read their own log output back want this one; so does anything that
// stamps its own arrival time.
func Plain(w io.Writer) *Logger { return New(SlogPlain(w)) }

// SlogPlain is Plain for a caller that needs the standard-library type.
func SlogPlain(w io.Writer) *slog.Logger {
	return slog.New(NewPlainHandler(w, slog.LevelDebug))
}
