package maintenance

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestRenewalWaitsForIndependentPinnedVerification(t *testing.T) {
	source, target := binaries(t)
	directory, r, _, _ := deployment(t, source, target)
	if err := change(t.Context(), directory, r.ID, func(r *Record) error {
		r.Phase = "healthy"
		r.ReadyPID = os.Getpid()
		r.ReadyAt = time.Now()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	startup := &Startup{directory: directory, id: r.ID}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := startup.AwaitVerification(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("receipt was treated as independent acknowledgement", err)
	}
	done := make(chan error, 1)
	bounded, stop := context.WithTimeout(t.Context(), 2*time.Second)
	defer stop()
	go func() { done <- startup.AwaitVerification(bounded) }()
	if err := SetPhase(t.Context(), directory, r.ID, "completed", ""); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal("committed helper acknowledgement was not observed", err)
	}
	if err := change(t.Context(), directory, r.ID, func(r *Record) error { r.ReadyPID++; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := startup.AwaitVerification(t.Context()); err == nil {
		t.Fatal("foreign process acknowledged this startup")
	}
	if err := (&Startup{recovered: true}).AwaitVerification(t.Context()); err != nil {
		t.Fatal("explicit offline recovery waits for a nonexistent helper", err)
	}
}
