package mgmt

// The management plane's audit log: a bounded, in-memory record of who changed
// what and whether it worked. It is what the caveats in the package README once
// said did not exist — "no audit log, no accounts" — minus the accounts part:
// there is one actor, the bearer-token holder, and the log says which mutation
// that actor made, to which entity, and with what outcome.
//
// It is deliberately in-memory and bounded (200 entries): it answers "what has
// happened since the supervisor started" for an operator investigating a fleet,
// not "what happened last month" — that is the supervisor's own log file's job,
// and persisting this would need storage, rotation and a format decision that
// the stdlib-only contract would make painful for no benefit.

import (
	"sync"
	"time"
)

// auditEvent is one recorded mutation.
type auditEvent struct {
	Time    time.Time `json:"time"`
	Action  string    `json:"action"`  // e.g. "listener.create", "profile.delete"
	Name    string    `json:"name"`    // the entity it happened to
	Outcome string    `json:"outcome"` // "ok", or the error message on failure
}

// auditCapacity bounds the ring. 200 is a few hours of active panel use and
// plenty of "what changed recently" context.
const auditCapacity = 200

// auditLog is a mutex-guarded ring of auditEvent.
type auditLog struct {
	mu     sync.Mutex
	events []auditEvent
}

func newAuditLog() *auditLog { return &auditLog{} }

// record appends one event, evicting the oldest once the ring is full.
func (a *auditLog) record(action, name string, err error) {
	outcome := "ok"
	if err != nil {
		outcome = err.Error()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, auditEvent{
		Time: time.Now(), Action: action, Name: name, Outcome: outcome,
	})
	if len(a.events) > auditCapacity {
		a.events = a.events[len(a.events)-auditCapacity:]
	}
}

// recent returns up to n events, newest first.
func (a *auditLog) recent(n int) []auditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n <= 0 || n > len(a.events) {
		n = len(a.events)
	}
	out := make([]auditEvent, n)
	for i := range out {
		out[i] = a.events[len(a.events)-1-i]
	}
	return out
}
