package lightweight

import (
	"bytes"
	"errors"
	"net"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight/congestion"
)

func TestFixedMetadataCharges(t *testing.T) {
	if reflect.TypeFor[ownedBuffer]().Size() > bufferCharge {
		t.Fatal("buffer descriptor exceeds its memory charge")
	}
	for _, algorithm := range []string{"reno", "cubic", "bbr"} {
		controller, err := congestion.New(algorithm, congestion.Config{MSS: 1460})
		if err != nil {
			t.Fatal(err)
		}
		footprint := reflect.TypeFor[TCPConn]().Size() + reflect.TypeOf(controller).Elem().Size() +
			64*(reflect.TypeFor[*sendSegment]().Size()+reflect.TypeFor[receiveChunk]().Size())
		if footprint > connectionCharge {
			t.Fatalf("%s connection and retained queues need %d bytes, charge %d", algorithm, footprint, connectionCharge)
		}
	}
}

func TestSendDescriptorOwnershipAndBudget(t *testing.T) {
	if reflect.TypeFor[sendSegment]().Size() > segmentCharge {
		t.Fatal("descriptor exceeds retained-memory charge")
	}
	link, _ := memoryPair()
	s, err := New(Config{MemoryLimit: 1 << 20}, link)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	owner, err := s.buffers.get(1000)
	if err != nil || !s.reserve(segmentCharge) {
		t.Fatalf("reserve descriptor: %v", err)
	}
	v := s.buffers.takeSegment()
	*v = sendSegment{owner: owner, data: owner.data, sacked: true, lossReported: true, transmissions: 2, delivered: 100}
	cost := owner.cost + segmentCharge
	s.buffers.releaseSegment(v)
	if s.Stats().MemoryBytes != int64(cost) || s.Stats().CachedBytes != int64(cost) {
		t.Fatalf("cache hid or doubled retained bytes: %+v", s.Stats())
	}
	if !s.reserve(segmentCharge) {
		t.Fatal("reserve replacement")
	}
	again := s.buffers.takeSegment()
	if again != v || !reflect.ValueOf(*again).IsZero() {
		t.Fatal("descriptor was not cleared before reuse")
	}
	// Give the checked-out descriptor its own payload ownership before return.
	owner, err = s.buffers.get(1000)
	if err != nil {
		t.Fatal(err)
	}
	*again = sendSegment{owner: owner, data: owner.data}
	s.buffers.releaseSegment(again)
	if !s.reserve((1 << 20) - 100) {
		t.Fatal("cached metadata prevented memory-pressure reclamation")
	}
	s.release((1 << 20) - 100)
	_ = s.Close()
	if s.Stats().MemoryBytes != 0 || s.Stats().CachedBytes != 0 {
		t.Fatal("descriptor cache survived close")
	}
}

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
		if !s.reserve(segmentCharge) {
			t.Fatal("reserve metadata")
		}
		v := s.buffers.takeSegment()
		b, err = s.buffers.get(100)
		if err != nil {
			t.Fatal(err)
		}
		*v = sendSegment{owner: b, data: b.data}
		s.buffers.releaseSegment(v)
		if s.Stats().CachedBytes == 0 {
			t.Fatal("released buffer was not cached")
		}
		time.Sleep(5 * time.Second)
		if s.Stats().MemoryBytes != 0 || s.Stats().CachedBytes != 0 || s.buffers.expiring.Load() {
			t.Fatal("idle cache retained traffic buffers or periodic timer")
		}
	})
}
