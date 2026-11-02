//go:build linux && !android

package sshserver

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
)

func TestConnectionNetworkClosedRejectsAcquire(t *testing.T) {
	group := &connectionNetwork{ctx: context.Background(), closed: true}
	if _, err := group.acquire(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("closed SSH connection must reject new shared sessions")
	}
}

func TestConnectionNetworkReferenceCounting(t *testing.T) {
	// This test exercises idempotent release and shutdown without privileged
	// TUN access. Namespace sharing itself is covered by sessionnet CI.
	group := &connectionNetwork{ctx: context.Background(), refs: 2}
	group.release()
	if group.refs != 1 {
		t.Fatalf("first session should retain the shared network: %d", group.refs)
	}
	group.release()
	if group.refs != 0 {
		t.Fatalf("last session should release the shared network: %d", group.refs)
	}
	group.release()
	group.Close()
	group.Close()
	if group.refs != 0 || !group.closed {
		t.Fatal("repeated releases and shutdown must be safe")
	}
	if _, err := group.acquire(); err == nil {
		t.Fatal("new session acquired a closed SSH connection")
	}
}

type failingCleanupCloser struct {
	err error
}

func (c failingCleanupCloser) Close() error {
	return c.err
}

func TestConnectionNetworkCleanupDoesNotLogSensitiveErrors(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	secret := "password=example-secret AuthKey=example-key preauthKey=example-preauth"
	closeConnectionNetwork(nil, failingCleanupCloser{err: errors.New(secret)}, nil)

	logged := output.String()
	if !strings.Contains(logged, "component=\"packet stack\"") {
		t.Fatalf("cleanup log did not identify the failing component: %q", logged)
	}
	if strings.Contains(logged, secret) || strings.Contains(logged, "example-secret") ||
		strings.Contains(logged, "example-key") || strings.Contains(logged, "example-preauth") {
		t.Fatal("cleanup error leaked sensitive values into logs")
	}
}
