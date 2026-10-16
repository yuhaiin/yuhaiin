package lightweight

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

func TestBufferOwnershipAndPressure(t *testing.T) {
	link, _ := memoryPair()
	s, err := New(Config{MemoryLimit: 1 << 20}, link)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	b, err := s.buffers.get(1460)
	if err != nil {
		t.Fatal(err)
	}
	copy(b.data, bytes.Repeat([]byte{0xa5}, 1460))
	b.hold()
	b.release()
	if s.Stats().CachedBytes != 0 || b.data[100] != 0xa5 {
		t.Fatal("shared buffer released before its last owner")
	}
	b.release()
	if s.Stats().CachedBytes == 0 {
		t.Fatal("released packet was not reusable")
	}
	again, err := s.buffers.get(1460)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.data) != 1460 || cap(again.data) < 1460 {
		t.Fatal("invalid lease length")
	}
	again.release()
	if !s.reserve((1 << 20) - 100) {
		t.Fatal("inactive cache prevented bounded allocation")
	}
	if s.Stats().MemoryBytes > 1<<20 {
		t.Fatal("pool escaped global budget")
	}
	s.release((1 << 20) - 100)
	_ = s.Close()
	if s.Stats().MemoryBytes != 0 || s.Stats().CachedBytes != 0 {
		t.Fatalf("pool retained memory after close: %+v", s.Stats())
	}
	if _, err = s.buffers.get(64); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("lease after close: %v", err)
	}
}

func TestLargeBuffersAreNotCached(t *testing.T) {
	link, _ := memoryPair()
	s, err := New(Config{}, link)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	b, err := s.buffers.get(65575)
	if err != nil {
		t.Fatal(err)
	}
	b.release()
	if s.Stats().MemoryBytes != 0 || s.Stats().CachedBytes != 0 {
		t.Fatal("large datagram remained in pool")
	}
}

func TestBufferCacheIdleReclamation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		link, _ := memoryPair()
		s, err := New(Config{}, link)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		b, err := s.buffers.get(16384)
		if err != nil {
			t.Fatal(err)
		}
		b.release()
		if s.Stats().CachedBytes == 0 {
			t.Fatal("released buffer was not cached")
		}
		time.Sleep(5 * time.Second)
		if s.Stats().MemoryBytes != 0 || s.Stats().CachedBytes != 0 || s.buffers.expiring.Load() {
			t.Fatal("idle cache retained traffic buffers or periodic timer")
		}
	})
}
