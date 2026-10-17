package lightweight

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"sync"
)

const pingCharge = 128

// PingRequest owns an ICMP Echo request independently of the packet reader.
// Reply preserves its identifier, sequence and payload. After ReceivePing,
// the consumer owns the retained packet and must bound outstanding requests.
type PingRequest struct {
	Source, Destination netip.Addr
	stack               *Stack
	packet              []byte
	once                sync.Once
	replyErr            error
}

// ReceivePing transfers one queued request to its consumer. ForwardPing must
// be explicitly enabled. The queue is bounded and charged to the stack's memory
// budget until handoff; it is drained by Close.
func (s *Stack) ReceivePing(ctx context.Context) (*PingRequest, error) {
	if s.closed() {
		return nil, net.ErrClosed
	}
	if !s.config.ForwardPing {
		return nil, ErrUnsupported
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.done:
		return nil, net.ErrClosed
	case request := <-s.pings:
		s.release(len(request.packet) + pingCharge)
		if s.closed() {
			return nil, net.ErrClosed
		}
		return request, nil
	}
}
func (s *Stack) forwardPing(p Packet) {
	if s.closed() {
		return
	}
	charge := len(p.Data) + pingCharge
	if !s.reserve(charge) {
		s.drops.Add(1)
		return
	}
	request := &PingRequest{Source: p.Source, Destination: p.Destination, stack: s, packet: bytes.Clone(p.Data)}
	select {
	case s.pings <- request:
	default:
		s.release(charge)
		s.drops.Add(1)
	}
}

// Reply emits at most one response. A nil result produces Echo Reply; an error
// produces a quoted Destination Unreachable, never a successful Echo Reply.
// No packet is emitted after Close, and retained input is released on return.
func (r *PingRequest) Reply(result error) error {
	r.once.Do(func() {
		defer func() { r.packet = nil }()
		if r.stack.closed() {
			r.replyErr = net.ErrClosed
			return
		}
		p, err := ParsePacket(r.packet)
		if err != nil {
			r.replyErr = err
			return
		}
		if result == nil {
			r.replyErr = r.stack.echoReply(p)
			return
		}
		typ, code := byte(3), byte(1) // IPv4 host unreachable.
		if p.Protocol == 58 {
			typ, code = 1, 3 // IPv6 address unreachable.
		}
		r.replyErr = r.stack.writeICMPError(p, typ, code, 0)
	})
	return r.replyErr
}
