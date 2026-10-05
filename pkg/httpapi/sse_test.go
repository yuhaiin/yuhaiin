package httpapi

import (
	"errors"
	"net/http/httptest"
	"testing"
	"time"
)

type deadlineSSEWriter struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
	flushErr  error
}

func (w *deadlineSSEWriter) SetWriteDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	return nil
}

func (w *deadlineSSEWriter) FlushError() error { return w.flushErr }

func TestSSEBoundsEachWriteAndPropagatesFlushErrors(t *testing.T) {
	failure := errors.New("write timed out")
	w := &deadlineSSEWriter{ResponseRecorder: httptest.NewRecorder(), flushErr: failure}
	before := time.Now()
	if err := writeSSEJSON(w, "test", struct{}{}); !errors.Is(err, failure) {
		t.Fatalf("flush error=%v", err)
	}
	if len(w.deadlines) != 2 || !w.deadlines[0].After(before) || !w.deadlines[1].IsZero() {
		t.Fatalf("write deadline not set and cleared: %v", w.deadlines)
	}
}
