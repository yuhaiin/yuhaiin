package mgmt

// The supervisor's in-memory log ring. Every line the supervisor and the
// management API write to their shared logger is captured here and served at
// GET /api/logs, so the panel can answer "why is this listener in error state"
// without the operator SSHing in to read stdout.
//
// It is deliberately bounded and in-memory, like the audit log: it answers
// "what has happened since the supervisor started", not "what happened last
// month" -- the process's own stdout logger is the durable record, and the
// ring is a convenience view of the tail of it.

import (
	"sync"
	"time"
)

// logCapacity bounds the ring. Log lines are noisier than audit events (a line
// per API request, per listener build), so the ring is bigger; 1000 lines is
// still a rounding error of memory and covers a long debugging session.
const logCapacity = 1000

// LogEntry is one captured line.
type LogEntry struct {
	Time time.Time `json:"time"`
	Line string    `json:"line"`
}

// LogRing is a mutex-guarded ring of the most recent log lines, newest last as
// received. It implements io.Writer so it can sit at the end of the same
// MultiWriter the process logger already writes to, with zero changes to how
// anything logs.
type LogRing struct {
	mu    sync.Mutex
	lines []LogEntry
}

func NewLogRing() *LogRing { return &LogRing{} }

// Write appends the log.Logger-flavoured chunk to the ring, splitting on
// newlines so each entry is one line with one timestamp.
func (r *LogRing) Write(p []byte) (int, error) {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	start := 0
	for i, b := range p {
		if b == '\n' {
			if i > start {
				r.push(now, string(p[start:i]))
			}
			start = i + 1
		}
	}
	if start < len(p) {
		r.push(now, string(p[start:]))
	}
	return len(p), nil
}

// push appends one line under r.mu (the caller holds it), evicting the oldest
// once the ring is full.
func (r *LogRing) push(now time.Time, line string) {
	r.lines = append(r.lines, LogEntry{Time: now, Line: line})
	if len(r.lines) > logCapacity {
		r.lines = r.lines[len(r.lines)-logCapacity:]
	}
}

// Recent returns up to n entries, newest first -- the shape the API serves and
// the panel renders. A negative or zero n returns everything.
func (r *LogRing) Recent(n int) []LogEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n <= 0 || n > len(r.lines) {
		n = len(r.lines)
	}
	out := make([]LogEntry, n)
	for i := range out {
		out[i] = r.lines[len(r.lines)-1-i]
	}
	return out
}
