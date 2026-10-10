package globalprotect

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestReconnectBackoffCapsAndJitters(t *testing.T) {
	for _, test := range []struct {
		delay time.Duration
		want  time.Duration
	}{
		{delay: 0, want: time.Second},
		{delay: time.Second, want: 2 * time.Second},
		{delay: 2 * time.Second, want: 4 * time.Second},
		{delay: 32 * time.Second, want: maximumReconnectDelay},
		{delay: maximumReconnectDelay, want: maximumReconnectDelay},
	} {
		if got := nextReconnectDelay(test.delay); got != test.want {
			t.Errorf("nextReconnectDelay(%s) = %s, want %s", test.delay, got, test.want)
		}
	}

	delay := 10 * time.Second
	for range 100 {
		got := jitterReconnectDelay(delay)
		if got < 8*time.Second || got > delay {
			t.Fatalf("jitterReconnectDelay(%s) = %s, want [8s, 10s]", delay, got)
		}
	}
}

func TestReconnectSupervisorRetriesAfterDisconnect(t *testing.T) {
	initial := &Client{done: make(chan struct{})}
	initial.mu.Lock()
	initial.failure = errors.New("temporary network failure")
	initial.mu.Unlock()
	reconnected := &Client{done: make(chan struct{})}
	var attempts atomic.Int32
	manager := newReconnectingClient(Config{}, initial, func(context.Context, Config) (*Client, error) {
		if attempts.Add(1) == 1 {
			return nil, errors.New("temporary network failure")
		}
		return reconnected, nil
	})
	manager.initialDelay = time.Millisecond
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		manager.run()
	}()
	close(initial.done)

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	for {
		manager.mu.Lock()
		client, changed := manager.client, manager.changed
		manager.mu.Unlock()
		if client == reconnected {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("reconnect supervisor did not establish a replacement client")
		case <-changed:
		}
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("reconnect attempts = %d, want 2", got)
	}

	manager.cancel()
	select {
	case <-runDone:
	case <-ctx.Done():
		t.Fatal("reconnect supervisor did not stop after cancellation")
	}
}

func TestReconnectSupervisorWaitsForDemandAfterIdleDisconnect(t *testing.T) {
	initial := &Client{done: make(chan struct{})}
	initial.mu.Lock()
	initial.failure = errGatewayIdleDisconnect
	initial.mu.Unlock()
	reconnected := &Client{done: make(chan struct{})}
	var attempts atomic.Int32
	manager := newReconnectingClient(Config{}, initial, func(context.Context, Config) (*Client, error) {
		attempts.Add(1)
		return reconnected, nil
	})
	manager.initialDelay = 10 * time.Millisecond
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		manager.run()
	}()
	close(initial.done)

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	for {
		manager.mu.Lock()
		waiting, changed := manager.waitingForDemand, manager.changed
		manager.mu.Unlock()
		if waiting {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("idle disconnect did not wait for demand")
		case <-changed:
		}
	}

	timer := time.NewTimer(2 * manager.initialDelay)
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal("test context ended before checking idle retry")
	}
	if got := attempts.Load(); got != 0 {
		t.Fatalf("idle reconnect attempts = %d, want 0 before demand", got)
	}

	client, err := manager.current(ctx)
	if err != nil {
		t.Fatalf("get reconnecting client: %v", err)
	}
	if client != reconnected {
		t.Fatal("connection request received the wrong client")
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("idle reconnect attempts = %d, want 1 after demand", got)
	}

	manager.cancel()
	select {
	case <-runDone:
	case <-ctx.Done():
		t.Fatal("reconnect supervisor did not stop after cancellation")
	}
}

func TestReconnectSupervisorStopsAfterAuthenticationRejection(t *testing.T) {
	initial := &Client{done: make(chan struct{})}
	initial.mu.Lock()
	initial.failure = errors.New("temporary network failure")
	initial.mu.Unlock()
	var attempts atomic.Int32
	manager := newReconnectingClient(Config{}, initial, func(context.Context, Config) (*Client, error) {
		attempts.Add(1)
		return nil, errAuthenticationRejected
	})
	manager.initialDelay = time.Millisecond
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		manager.run()
	}()
	close(initial.done)

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	for {
		manager.mu.Lock()
		failure, changed := manager.failure, manager.changed
		manager.mu.Unlock()
		if failure != nil {
			if !errors.Is(failure, errAuthenticationRejected) {
				t.Fatalf("terminal failure = %v, want authentication rejection", failure)
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("authentication rejection was not reported")
		case <-changed:
		}
	}
	select {
	case <-runDone:
	case <-ctx.Done():
		t.Fatal("reconnect supervisor continued after authentication rejection")
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("reconnect attempts = %d, want 1", got)
	}
	if _, err := manager.current(ctx); !errors.Is(err, errAuthenticationRejected) {
		t.Fatalf("current client error = %v, want authentication rejection", err)
	}
	manager.cancel()
}
