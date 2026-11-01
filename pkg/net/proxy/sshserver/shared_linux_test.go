//go:build linux && !android

package sshserver

import (
	"context"
	"errors"
	"testing"
)

func TestConnectionNetworkClosedRejectsAcquire(t *testing.T) {
	group := &connectionNetwork{ctx: context.Background(), closed: true}
	if _, err := group.acquire(); !errors.Is(err, context.Canceled) && err == nil {
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
