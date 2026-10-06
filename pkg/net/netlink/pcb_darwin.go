package netlink

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
)

// Share only queries arriving during a kernel read. Clear the in-flight
// snapshot as soon as that read completes, even if earlier readers are still
// scanning it: a steady stream of readers must never keep stale data alive.
type pcbQuery struct {
	mu      sync.Mutex
	current *pcbSnapshot
	spare   []byte
}

type pcbSnapshot struct {
	ready   chan struct{}
	data    []byte
	err     error
	readers int
}

func (q *pcbQuery) acquire(read func([]byte) ([]byte, error)) *pcbSnapshot {
	q.mu.Lock()
	if s := q.current; s != nil {
		s.readers++
		q.mu.Unlock()
		<-s.ready
		return s
	}
	s := &pcbSnapshot{ready: make(chan struct{}), readers: 1}
	buf := q.spare
	q.spare = nil
	q.current = s
	q.mu.Unlock()
	s.data, s.err = read(buf)
	q.mu.Lock()
	q.current = nil
	close(s.ready)
	q.mu.Unlock()
	return s
}

// A completed read is never a cached result. Only recycle its backing array
// once every scanner has finished, and retain at most one reasonably sized
// buffer per protocol rather than keeping a peak-sized table indefinitely.
func (q *pcbQuery) release(s *pcbSnapshot) {
	q.mu.Lock()
	defer q.mu.Unlock()
	s.readers--
	if s.readers == 0 {
		if cap(s.data) <= 1<<20 && cap(s.data) > cap(q.spare) {
			q.spare = s.data[:0]
		}
		s.data = nil
	}
}

var tcpPCBQuery, udpPCBQuery pcbQuery

// Offsets follow XNU's xinpcb_n and xsocket_n (in_pcblist.c). Ports are
// network-endian; the PID is native-endian. Scan without allocating an index,
// which would otherwise cost more than the table for small query cohorts.
func findPCBPID(buf []byte, itemSize int, network string, src, dst netip.AddrPort) (uint32, error) {
	if itemSize < 176 {
		return 0, fmt.Errorf("invalid PCB record size: %d", itemSize)
	}
	src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
	if dst.IsValid() {
		dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	}
	var fallback uint32
	for i := 24; i+itemSize <= len(buf); i += itemSize {
		if src.Port() != binary.BigEndian.Uint16(buf[i+18:i+20]) {
			continue
		}
		flag := buf[i+44]
		var local, remote netip.Addr
		switch {
		case src.Addr().Is4() && flag&1 != 0:
			local = netip.AddrFrom4([4]byte(buf[i+76 : i+80]))
			remote = netip.AddrFrom4([4]byte(buf[i+60 : i+64]))
		case src.Addr().Is6() && flag&2 != 0:
			local = netip.AddrFrom16([16]byte(buf[i+64 : i+80]))
			remote = netip.AddrFrom16([16]byte(buf[i+48 : i+64]))
		default:
			continue
		}
		peerPort := binary.BigEndian.Uint16(buf[i+16 : i+18])
		if dst.IsValid() && (network == "tcp" || peerPort != 0) && (peerPort != dst.Port() || remote != dst.Addr()) {
			continue
		}
		pid := binary.NativeEndian.Uint32(buf[i+172 : i+176])
		if pid == 0 {
			continue
		}
		if local == src.Addr() {
			return pid, nil
		}
		if network == "udp" && local.IsUnspecified() && fallback == 0 {
			fallback = pid
		}
	}
	if fallback != 0 {
		return fallback, nil
	}
	return 0, fmt.Errorf("process for %s %s not found", network, src)
}
