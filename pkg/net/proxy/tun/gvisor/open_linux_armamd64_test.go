//go:build (linux && amd64) || (linux && arm64)

package gvisor

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
)

func TestFDBasedEndpointDrainsEveryQueueAndCloses(t *testing.T) {
	var readers, writers []int
	for range 2 {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		readers = append(readers, fds[0])
		writers = append(writers, fds[1])
	}
	t.Cleanup(func() { closeTunFDs(writers) })
	endpoint, err := fdbased.New(&fdbased.Options{
		FDs: readers, MTU: 1500, GRO: true, ProcessorsPerChannel: 1,
	})
	if err != nil {
		closeTunFDs(readers)
		t.Fatal(err)
	}
	e := &fdBasedEndpoint{LinkEndpoint: endpoint, fds: readers}
	t.Cleanup(func() {
		// Also release the real readers if the wrapper's Close deadlocks.
		endpoint.Attach(nil)
		closeTunFDs(readers)
	})
	dispatcher := &packetDispatcher{received: make(chan []byte, 2)}
	e.Attach(dispatcher)
	packet := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize+1)
	header.IPv4(packet).Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)), Protocol: uint8(header.TCPProtocolNumber), TTL: 64,
	})
	header.TCP(packet[header.IPv4MinimumSize:]).Encode(&header.TCPFields{
		SrcPort: 12345, DstPort: 443, DataOffset: header.TCPMinimumSize, Flags: header.TCPFlagAck,
	})
	packet[len(packet)-1] = 42
	// The first FD stays idle. The second must deliver its last GRO packet
	// without waiting for any additional traffic on either FD.
	if _, err := unix.Write(writers[1], packet); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-dispatcher.received:
		if !bytes.Equal(got, packet) {
			t.Fatal("packet corrupted")
		}
	case <-time.After(time.Second):
		t.Fatal("active FD or last GRO packet stalled behind idle reads")
	}

	done := make(chan struct{})
	go func() {
		var workers sync.WaitGroup
		for range 2 {
			workers.Go(e.Close)
		}
		workers.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("concurrent Close deadlocked with idle FD readers")
	}
	for _, fd := range readers {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			t.Fatalf("FD %d still open after Close: %v", fd, err)
		}
	}
	// Do not close the same descriptor numbers again: the runtime can reuse
	// them before test cleanup runs.
	readers = nil
	if e.IsAttached() {
		t.Fatal("endpoint still attached after Close")
	}
}
