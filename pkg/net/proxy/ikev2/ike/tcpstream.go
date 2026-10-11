package ike

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// TCP encapsulation of IKE and ESP (RFC 8229, updated by RFC 9329): one TCP
// connection to port 4500 carrying both, length-prefixed, for a network that
// blocks UDP.
//
//	initiator                               responder
//	    |--- TCP connect :4500 --------------->|
//	    |--- "IKETCP" ------------------------>|   once, originator only
//	    |--- [len][0,0,0,0][IKE_SA_INIT] ----->|
//	    |<-- [len][0,0,0,0][IKE_SA_INIT] ------|
//	    |--- [len][0,0,0,0][IKE_AUTH] -------->|
//	    |<-- [len][0,0,0,0][IKE_AUTH] ---------|
//	    |--- [len][ESP] ---------------------->|
//	    |<-- [len][ESP] -----------------------|
//
// The codec is in tcpframe.go; this file is the connection around it. Three
// things about the stream shape decide the design here:
//
//   - There is no port-500 phase and no NAT-T float. RFC 8229 section 3 puts
//     the whole exchange on TCP 4500 from the first octet, and the non-ESP
//     marker is present from the first IKE message rather than appearing after
//     a float. A stream also cannot be behind a NAT that rewrites its source
//     port between messages, so NAT detection has nothing to do -- the notify
//     payloads are still sent, because a responder that has not seen the stream
//     as TCP would otherwise mis-detect, and they cost nothing.
//   - A stream has exactly one writer. IKE control exchanges (DPD, rekey) run
//     on their own goroutine while the pump writes ESP, so every write takes
//     wmu. Two interleaved writes do not lose a datagram as they would on UDP;
//     they corrupt the frame boundary and desynchronise the stream permanently.
//   - MOBIKE does not apply. The TCP connection is the binding; an address
//     change breaks it, and the answer is to reconnect, not to send
//     UPDATE_SA_ADDRESSES on a socket that no longer exists.
type TCPStream struct {
	c net.Conn
	r *tcpReader

	wmu sync.Mutex
	// wbuf is the write scratch every framed write is assembled in, reused
	// under wmu so the ESP path allocates nothing per packet.
	wbuf []byte
}

var errTCPFrameNotIKE = errors.New("ike: TCP frame carries ESP where an IKE message was expected")

// dialTCPStream opens the RFC 8229 stream to a responder and sends the stream
// prefix. The prefix goes out immediately rather than being folded into the
// first message: a responder reads it before it will read a frame, so deferring
// it deadlocks a peer that has nothing to send first.
func dialTCPStream(host string, port int, timeout time.Duration, dial func(context.Context, string, string) (net.Conn, error)) (*TCPStream, error) {
	var c net.Conn
	var err error
	if dial != nil {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		c, err = dial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	} else {
		c, err = net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	}
	if err != nil {
		return nil, err
	}
	// Nagle would hold a small IKE message waiting for more to send, which on a
	// request/response control exchange means waiting for the answer to the
	// message it is holding.
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	if _, err := c.Write([]byte(tcpStreamPrefix)); err != nil {
		c.Close()
		return nil, fmt.Errorf("send stream prefix: %w", err)
	}
	return newTCPStream(c), nil
}

func newTCPStream(c net.Conn) *TCPStream {
	return &TCPStream{c: c, r: newTCPReader(c), wbuf: make([]byte, 0, 2048)}
}

// WriteIKE frames and sends one IKE message, with the non-ESP marker the format
// requires so the peer can tell it from ESP.
func (t *TCPStream) WriteIKE(pkt []byte) error {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	t.wbuf = appendTCPIKE(t.wbuf[:0], pkt)
	_, err := t.c.Write(t.wbuf)
	return err
}

// WriteESP frames and sends one ESP packet. No marker: a non-zero SPI is its
// own.
func (t *TCPStream) WriteESP(pkt []byte) error {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	t.wbuf = appendTCPFrame(t.wbuf[:0], pkt)
	_, err := t.c.Write(t.wbuf)
	return err
}

// WriteESPBatch sends several ESP packets as one write. A stream has no
// datagram boundary to preserve, so a burst off the GSO path becomes one
// syscall carrying several frames -- the stream equivalent of the sendmmsg the
// UDP path uses, and the reason the batch sender is not simply dropped here.
func (t *TCPStream) WriteESPBatch(pkts [][]byte) error {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	t.wbuf = t.wbuf[:0]
	for _, p := range pkts {
		t.wbuf = appendTCPFrame(t.wbuf, p)
	}
	_, err := t.c.Write(t.wbuf)
	return err
}

// ReadFrame returns the next frame's payload and whether it is an IKE message.
// The slice borrows the reader's buffer and is valid only until the next call,
// which is the same contract the datagram parsers keep.
func (t *TCPStream) ReadFrame() (pkt []byte, isIKE bool, err error) {
	frame, err := t.r.Next()
	if err != nil {
		return nil, false, err
	}
	if tcpFrameIsIKE(frame) {
		return frame[len(nonESPMarker):], true, nil
	}
	return frame, false, nil
}

// ReadIKE returns the next IKE message, and fails if an ESP packet arrives
// instead.
//
// It is only used during the handshake, where no Child SA exists yet and so no
// ESP can legitimately be in flight. Once the data path owns the stream it does
// the reading and hands IKE messages to Client.Deliver, exactly as the UDP path
// does.
func (t *TCPStream) ReadIKE() ([]byte, error) {
	pkt, isIKE, err := t.ReadFrame()
	if err != nil {
		return nil, err
	}
	if !isIKE {
		return nil, errTCPFrameNotIKE
	}
	// Copied out: the caller's message may outlive the reader's buffer, and the
	// handshake is not a hot path.
	out := make([]byte, len(pkt))
	copy(out, pkt)
	return out, nil
}

func (t *TCPStream) SetReadDeadline(d time.Time) error { return t.c.SetReadDeadline(d) }
func (t *TCPStream) LocalAddr() net.Addr               { return t.c.LocalAddr() }
func (t *TCPStream) RemoteAddr() net.Addr              { return t.c.RemoteAddr() }
func (t *TCPStream) Close() error                      { return t.c.Close() }

// udpAddrOf renders a stream endpoint as a *net.UDPAddr.
//
// Every address the IKE layer and the pump pass around is a *net.UDPAddr -- the
// NAT detection hashes, dataplane.Sender, espTunnel.PeerAddr. Over TCP those
// addresses are never used to *send* anything (the stream is the destination),
// but they are used as identity and hashed, so they must be the real endpoint
// and not a placeholder.
func udpAddrOf(a net.Addr) *net.UDPAddr {
	tcp, ok := a.(*net.TCPAddr)
	if !ok {
		return &net.UDPAddr{}
	}
	return &net.UDPAddr{IP: tcp.IP, Port: tcp.Port, Zone: tcp.Zone}
}
