package vlog

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
)

// TextHandler is the handler behind `-log-format text`, and its entire job is to
// print what the command has always printed:
//
//	2026/08/25 11:22:33.123456 ikev2: client 10.0.0.2 up
//
// That is `log.LstdFlags|log.Lmicroseconds` followed by the message, and it is
// load-bearing rather than nostalgic. Twenty-eight interop cells assert
// substrings of veepin's own log output, the management panel's ring shows the
// stream as free text, and every runbook in doc/usage quotes lines from it. A
// slog.TextHandler would render `time=... level=INFO msg="..."` instead —
// quoting the message, reordering the timestamp, and breaking all three at once.
//
// So the level is *used* (it decides what is written) and not *printed*. An
// operator who wants the level in the line asks for `-log-format json`, which is
// what json is for.
type TextHandler struct {
	mu    *sync.Mutex
	w     io.Writer
	level slog.Leveler
	attrs []slog.Attr
	group string
	// bare drops the timestamp, which is what log.New(w, "", 0) did. It exists
	// for the callers that read their own output back -- tests, and the panel's
	// log ring, which stamps its own arrival time.
	bare bool
}

// NewTextHandler builds one over w, writing every record at or above level.
//
// It lives here rather than in package main because the management plane needs
// it too: the supervisor's log ring is an io.Writer whose contents the panel
// serves as free text, so the lines it captures have to be these lines.
func NewTextHandler(w io.Writer, level slog.Leveler) *TextHandler {
	return &TextHandler{mu: &sync.Mutex{}, w: w, level: level}
}

// NewPlainHandler is NewTextHandler without the timestamp: one message per line
// and nothing else, which is what log.New(w, "", 0) wrote.
func NewPlainHandler(w io.Writer, level slog.Leveler) *TextHandler {
	return &TextHandler{mu: &sync.Mutex{}, w: w, level: level, bare: true}
}

func (h *TextHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level.Level()
}

func (h *TextHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	if !h.bare {
		// The exact layout of log.LstdFlags|log.Lmicroseconds, in local time.
		b.WriteString(r.Time.Format("2006/01/02 15:04:05.000000 "))
	}
	b.WriteString(r.Message)
	// Attributes are not what this tree logs -- vlog carries none -- but a
	// handler that dropped them silently would be a trap for whoever adds the
	// first one. They go on the end, space-separated, unquoted, in the shape
	// the message text already uses.
	appendAttr := func(a slog.Attr) {
		if a.Equal(slog.Attr{}) {
			return
		}
		b.WriteByte(' ')
		if h.group != "" {
			b.WriteString(h.group)
			b.WriteByte('.')
		}
		fmt.Fprintf(&b, "%s=%v", a.Key, a.Value.Any())
	}
	for _, a := range h.attrs {
		appendAttr(a)
	}
	r.Attrs(func(a slog.Attr) bool {
		appendAttr(a)
		return true
	})
	b.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, b.String())
	return err
}

func (h *TextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	out := *h
	out.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	return &out
}

func (h *TextHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	out := *h
	if h.group != "" {
		out.group = h.group + "." + name
	} else {
		out.group = name
	}
	return &out
}
