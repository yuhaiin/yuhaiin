package wireguard

import (
	"context"
	"sync"
	"testing"
)

func TestChannelDeviceCloseAfterParentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	d := NewChannelDevice(ctx, 1400)
	<-d.Events() // Initial link-up notification.
	cancel()
	var closers sync.WaitGroup
	for range 4 {
		closers.Go(func() { _ = d.Close() })
	}
	closers.Wait()
	select {
	case _, open := <-d.Events():
		if open {
			t.Fatal("unexpected event after Close")
		}
	default:
		t.Fatal("Close did not close events after parent cancellation")
	}
}
