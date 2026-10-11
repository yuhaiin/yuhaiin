package netapi

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

type failingCloseResolver struct {
	Resolver
	err    error
	closed bool
}

func (r *failingCloseResolver) Close() error {
	r.closed = true
	return r.err
}

func TestSetBootstrapDoesNotLogUpstreamCredentials(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	const credential = "bootstrap-test-secret"
	old := &failingCloseResolver{err: errors.New("upstream close: password=" + credential)}
	next := &failingCloseResolver{}
	b := &bootstrapResolver{r: old}
	b.SetBootstrap(next)
	if !old.closed || b.r != next {
		t.Fatal("bootstrap resolver was not replaced")
	}
	if strings.Contains(output.String(), credential) {
		t.Fatal("upstream credentials leaked into shutdown log")
	}
	if !strings.Contains(output.String(), "close bootstrap resolver failed") {
		t.Fatal("shutdown failure was not logged")
	}
}
