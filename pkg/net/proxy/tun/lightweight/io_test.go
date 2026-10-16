package lightweight

import (
	"context"
	"errors"
	"fmt"
	"go.uber.org/goleak"
	"io"
	"math"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type faultPacketIO struct {
	PacketIO
	reads, writes []error // Each direction has exactly one stack worker.
	stuck         atomic.Bool
	entered       chan struct{}
}

func (p *faultPacketIO) ReadPacket(b []byte) (int, error) {
	if len(p.reads) > 0 {
		err := p.reads[0]
		p.reads = p.reads[1:]
		return 0, fmt.Errorf("device read: %w", err)
	}
	return p.PacketIO.ReadPacket(b)
}
func (p *faultPacketIO) WritePacket(b []byte) error {
	if p.stuck.Load() {
		if p.entered != nil {
			select {
			case p.entered <- struct{}{}:
			default:
			}
		}
		return syscall.EAGAIN
	}
	if len(p.writes) > 0 {
		err := p.writes[0]
		p.writes = p.writes[1:]
		return fmt.Errorf("device write: %w", err)
	}
	return p.PacketIO.WritePacket(b)
}
func TestPacketIORecoversTransientErrors(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	a, b := memoryPair()
	p := &faultPacketIO{PacketIO: a, reads: []error{syscall.EINTR, syscall.EAGAIN, syscall.ENOBUFS, io.ErrShortBuffer}, writes: []error{syscall.EINTR, syscall.EAGAIN, syscall.ENOBUFS}}
	s, err := New(Config{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}, p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	peer, err := New(Config{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.2")}}, b)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	server, err := peer.ListenUDP(netip.MustParseAddrPort("192.0.2.2:80"))
	if err != nil {
		t.Fatal(err)
	}
	client, err := s.DialUDP(netip.AddrPort{}, server.local)
	if err != nil {
		t.Fatal(err)
	}
	_ = server.SetDeadline(time.Now().Add(time.Second))
	if _, err = client.Write([]byte("after transient failures")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 100)
	n, _, err := server.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "after transient failures" {
		t.Fatalf("device recovery: %q %v", buf[:n], err)
	}
	if _, err = server.WriteTo(buf[:n], net.UDPAddrFromAddrPort(client.local)); err != nil {
		t.Fatal(err)
	}
	_ = client.SetDeadline(time.Now().Add(time.Second))
	n, err = client.Read(buf)
	if err != nil || string(buf[:n]) != "after transient failures" {
		t.Fatalf("read recovery: %q %v", buf[:n], err)
	}
	select {
	case <-s.Done():
		t.Fatal("transient device error shut down stack")
	default:
	}
}
func TestPacketIOCloseInterruptsRetry(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	link, _ := memoryPair()
	p := &faultPacketIO{PacketIO: link, entered: make(chan struct{}, 1)}
	p.stuck.Store(true)
	s, err := New(Config{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}, p)
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.DialUDP(netip.AddrPort{}, netip.MustParseAddrPort("192.0.2.2:80"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = u.Write([]byte("pending retry")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	select {
	case <-p.entered:
	case <-ctx.Done():
		t.Fatal("writer did not enter retry path")
	}
	done := make(chan error, 1)
	go func() { done <- s.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("close blocked behind transient write")
	}
	if s.Stats().MemoryBytes != 0 {
		t.Fatal("close retained retry buffer")
	}
}
func TestClosedPacketIOIsNotTransient(t *testing.T) {
	if temporaryPacketError(fmt.Errorf("closed: %w", net.ErrClosed)) {
		t.Fatal("closed device was retryable")
	}
	if temporaryPacketError(io.EOF) {
		t.Fatal("EOF was retryable")
	}
}
func TestAllocationLengthBounds(t *testing.T) {
	link, _ := memoryPair()
	s, err := New(Config{}, link)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	src, dst := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	for _, n := range []int{-1, math.MinInt, math.MaxInt, 65576} {
		if _, err := s.buffers.get(n); !errors.Is(err, ErrLimit) {
			t.Fatalf("lease length %d: %v", n, err)
		}
		if s.buffers.canGet(n) {
			t.Fatalf("invalid capacity admitted: %d", n)
		}
		if _, err := ipHeaderSize(src, dst, n); !errors.Is(err, ErrMTU) {
			t.Fatalf("IP payload length %d: %v", n, err)
		}
	}
	if s.Stats().MemoryBytes != 0 {
		t.Fatal("invalid length reserved allocation")
	}
	for _, src := range []netip.Addr{src, netip.MustParseAddr("2001:db8::1")} {
		dst := dst
		if src.Is6() {
			dst = netip.MustParseAddr("2001:db8::2")
		}
		limit := 65535
		if src.Is4() {
			limit -= 20
		}
		if _, err := ipHeaderSize(src, dst, limit); err != nil {
			t.Fatal(err)
		}
		if _, err := ipHeaderSize(src, dst, limit+1); !errors.Is(err, ErrMTU) {
			t.Fatal("oversize IP payload accepted")
		}
	}
}

func TestTCPOutputRejectsOversizeBeforeAllocation(t *testing.T) {
	link, _ := memoryPair()
	s, err := New(Config{}, link)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := s.newTCP(flowKey{netip.MustParseAddrPort("192.0.2.1:80"), netip.MustParseAddrPort("192.0.2.2:90")}, Established)
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	sent := c.output(c.sndNxt, flagACK, make([]byte, 65535))
	got := c.err
	c.mu.Unlock()
	if sent || !errors.Is(got, ErrMTU) || s.Stats().MemoryBytes != 0 {
		t.Fatalf("oversize output sent=%v err=%v memory=%d", sent, got, s.Stats().MemoryBytes)
	}
}
