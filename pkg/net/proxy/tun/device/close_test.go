package device

import (
	"errors"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"weak"

	wun "github.com/tailscale/wireguard-go/tun"
)

type closingTestDevice struct {
	wun.Device
	events   chan wun.Event
	closed   chan struct{}
	reading  chan struct{}
	closes   atomic.Int32
	readOnce sync.Once
}

func (d *closingTestDevice) BatchSize() int           { return 1 }
func (d *closingTestDevice) Events() <-chan wun.Event { return d.events }
func (d *closingTestDevice) Read([]byte, []wun.ReadPacket) (int, error) {
	d.readOnce.Do(func() { close(d.reading) })
	<-d.closed
	return 0, os.ErrClosed
}
func (d *closingTestDevice) Close() error {
	if d.closes.Add(1) == 1 {
		close(d.closed)
	}
	return nil
}

func TestDeviceCloseDrainsEventsAndReleasesReadBuffer(t *testing.T) {
	native := &closingTestDevice{events: make(chan wun.Event, 1), closed: make(chan struct{}), reading: make(chan struct{})}
	produced, exited := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(exited)
		defer close(native.events)
		for range 64 {
			native.events <- wun.EventMTUUpdate
		}
		close(produced)
		<-native.closed
	}()
	// Also release the intentionally blocked producer when testing broken code.
	t.Cleanup(func() {
		_ = native.Close()
		for range native.events {
		}
	})
	d := NewDevice(native, 0, 9000, true)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_, _ = d.Read([][]byte{make([]byte, 9000)}, make([]int, 1))
	}()
	<-native.reading
	slab := weak.Make(&d.slab[0])
	select {
	case <-produced:
	case <-time.After(time.Second):
		t.Error("device events are not consumed")
	}
	var closers sync.WaitGroup
	for range 4 {
		closers.Go(func() { _ = d.Close() })
	}
	closers.Wait()
	<-readDone
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Error("event producer survived Close")
	}
	if got := native.closes.Load(); got != 1 {
		t.Errorf("underlying Close called %d times", got)
	}
	runtime.GC()
	runtime.GC()
	if slab.Value() != nil {
		t.Error("closed device retains its read slab")
	}
	if _, err := d.Read([][]byte{make([]byte, 9000)}, make([]int, 1)); !errors.Is(err, os.ErrClosed) {
		t.Errorf("Read after Close = %v, want os.ErrClosed", err)
	}
	runtime.KeepAlive(d)
}

type nativeCloseErrorDevice struct {
	wun.Device
	events   chan wun.Event
	closeErr error
	closes   atomic.Int32
}

func (d *nativeCloseErrorDevice) Events() <-chan wun.Event { return d.events }
func (d *nativeCloseErrorDevice) Close() error {
	d.closes.Add(1)
	return d.closeErr
}

func TestDeviceCloseNativeCancellationRace(t *testing.T) {
	cancelClosed := &os.PathError{Op: "write", Path: "|1", Err: os.ErrClosed}
	queueClosed := &os.PathError{Op: "close", Path: "/dev/net/tun", Err: os.ErrClosed}
	failedCancel := &os.PathError{Op: "write", Path: "|1", Err: os.ErrPermission}
	for _, tc := range []struct {
		name       string
		closeErr   error
		withEvents bool
		want       error
	}{
		{"cancellation pipe already closed", cancelClosed, true, nil},
		{"native queue close failure", queueClosed, true, os.ErrClosed},
		{"unexpected netlink cancellation failure", failedCancel, true, os.ErrPermission},
		{"unmonitored device close failure", cancelClosed, false, os.ErrClosed},
		{"joined close failures", errors.Join(cancelClosed, os.ErrPermission), true, os.ErrPermission},
	} {
		t.Run(tc.name, func(t *testing.T) {
			native := &nativeCloseErrorDevice{closeErr: tc.closeErr}
			if tc.withEvents {
				native.events = make(chan wun.Event)
				close(native.events)
			}
			dev := NewDevice(native, 0, 1500, false)
			for range 2 {
				err := dev.Close()
				if tc.want == nil {
					if err != nil {
						t.Fatalf("closed netlink cancellation pipe should not fail shutdown: %v", err)
					}
				} else if !errors.Is(err, tc.want) {
					t.Fatalf("Close() = %v, want %v", err, tc.want)
				}
			}
			if got := native.closes.Load(); got != 1 {
				t.Fatalf("underlying device closed %d times; want one", got)
			}
		})
	}
}
