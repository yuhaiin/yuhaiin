package lightweight

import (
	"errors"
	"os"
	"testing"
	"testing/synctest"
	"time"
)

func TestTCPReadDeadlineChanges(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, c, _, _ := passiveWire(t, 100, 1000)
		result := make(chan error, 1)
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		go func() { _, err := c.Read(make([]byte, 1)); result <- err }()
		synctest.Wait()
		_ = c.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
		time.Sleep(15 * time.Millisecond)
		synctest.Wait()
		select {
		case err := <-result:
			t.Fatalf("old deadline fired after extension: %v", err)
		default:
		}
		_ = c.SetReadDeadline(time.Time{})
		time.Sleep(30 * time.Millisecond)
		synctest.Wait()
		select {
		case err := <-result:
			t.Fatalf("cleared deadline fired: %v", err)
		default:
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
		time.Sleep(5 * time.Millisecond)
		synctest.Wait()
		if err := <-result; !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("reader deadline: %v", err)
		}
		if c.State() != Established {
			t.Fatal("socket deadline aborted transport")
		}
		s.scheduler.mu.Lock()
		scheduled := c.job.index >= 0
		s.scheduler.mu.Unlock()
		if scheduled {
			t.Fatal("expired read deadline retained a periodic job")
		}
	})
}

func TestTCPWriteDeadlineUnderZeroWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, c, _, _ := passiveConfigured(t, 100, 0, Config{SendBuffer: 4096}, false)
		_ = c.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
		result := make(chan error, 1)
		go func() {
			n, err := c.Write(make([]byte, 8192))
			if n != 4096 {
				t.Errorf("accepted %d bytes, want send-buffer capacity", n)
			}
			result <- err
		}()
		synctest.Wait()
		c.mu.Lock()
		reader := watch(&c.changed)
		c.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		synctest.Wait()
		if err := <-result; !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("writer deadline: %v", err)
		}
		select {
		case <-reader:
			t.Fatal("write deadline woke unrelated reader")
		default:
		}
		if c.State() != Established {
			t.Fatal("write deadline aborted transport")
		}
	})
}

// Mutex contention is not a durable wait in synctest. Exercise serialized
// concurrent readers with real time and a bounded timeout instead.
func TestTCPConcurrentReadersDeadline(t *testing.T) {
	_, c, _, _ := passiveWire(t, 100, 1000)
	_ = c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	result := make(chan error, 2)
	for range 2 {
		go func() { _, err := c.Read(make([]byte, 1)); result <- err }()
	}
	for range 2 {
		select {
		case err := <-result:
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("reader deadline: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("concurrent reader remained blocked after deadline")
		}
	}
}
