package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

// The peer deliberately loses SCCRQ and sends an ACK beyond the sent window.
// A client must retry the same Ns, then complete a bidirectional v3 session.
func TestControlLossAndSessionLifecycle(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	conn, err := net.Dial("udp", peer.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		send := func(to net.Addr, p packet) error { _, err := peer.WriteTo(p.encode(), to); return err }
		buf := make([]byte, 4096)
		requests := 0
		var tunnel, session uint32
		var cookie []byte
		for {
			_ = peer.SetReadDeadline(time.Now().Add(4 * time.Second))
			n, from, err := peer.ReadFrom(buf)
			if err != nil {
				finished <- err
				return
			}
			p, err := decode(buf[:n], "")
			if err != nil {
				finished <- err
				return
			}
			switch p.message() {
			case msgSCCRQ:
				requests++
				tunnel = binary.BigEndian.Uint32(p.value(61))
				if p.ns != 0 {
					finished <- fmt.Errorf("SCCRQ retry changed Ns: %d", p.ns)
					return
				}
				if requests == 1 {
					err = send(from, packet{version: 3, control: true, tunnel: tunnel, nr: 100, avps: []avp{attr(0, u16(msgACK))}})
				} else {
					err = send(from, packet{version: 3, control: true, tunnel: tunnel, nr: 1, avps: []avp{attr(0, u16(msgSCCRP)), attr(7, []byte("fixture")), attr(60, u32(42)), attr(61, u32(42)), attr(62, u16(5))}})
				}
			case msgSCCCN:
				err = send(from, packet{version: 3, control: true, tunnel: tunnel, ns: 1, nr: p.ns + 1, avps: []avp{attr(0, u16(msgACK))}})
			case msgICRQ:
				session = binary.BigEndian.Uint32(p.value(63))
				cookie = bytes.Clone(p.value(65))
				err = send(from, packet{version: 3, control: true, tunnel: tunnel, ns: 1, nr: p.ns + 1, avps: []avp{attr(0, u16(msgICRP)), attr(63, u32(43)), attr(64, u32(session)), attr(71, u16(3)), attr(65, []byte{1, 2, 3, 4})}})
			case msgICCN:
				if err = send(from, packet{version: 3, control: true, tunnel: tunnel, ns: 2, nr: p.ns + 1, avps: []avp{attr(0, u16(msgACK))}}); err != nil {
					finished <- err
					return
				}
			case msgStop:
				if requests != 2 {
					finished <- fmt.Errorf("SCCRQ attempts: %d", requests)
					return
				}
				finished <- nil
				return
			case 0:
				if p.control {
					continue
				}
				if p.session != 43 || !bytes.HasPrefix(p.payload, []byte{1, 2, 3, 4}) {
					finished <- fmt.Errorf("wrong outgoing session/cookie: %+v", p)
					return
				}
				data := make([]byte, 8)
				binary.BigEndian.PutUint16(data, 3)
				binary.BigEndian.PutUint32(data[4:], session)
				data = append(data, cookie...)
				data = append(data, p.payload[4:]...)
				_, err = peer.WriteTo(data, from)
			}
			if err != nil {
				finished <- err
				return
			}
		}
	}()
	s, err := Connect(ctx, Config{Version: 3}, conn)
	if err != nil {
		t.Fatal(err)
	}
	frame := bytes.Repeat([]byte{0xab}, 64)
	if err := s.WriteFrame(frame); err != nil {
		t.Fatal(err)
	}
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()
	got, err := s.ReadFrame()
	if err != nil || !bytes.Equal(got, frame) {
		t.Fatalf("echo %x, %v", got, err)
	}
	_ = s.Close()
	_ = s.Close()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if !errors.Is(s.Err(), net.ErrClosed) {
		t.Fatalf("closed session error: %v", s.Err())
	}
	if err := s.WriteFrame(frame); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after close: %v", err)
	}
}

func TestConnectCancellationClosesTransport(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	conn, err := net.Dial("udp", peer.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = Connect(ctx, Config{Version: 2}, conn)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancellation error: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancellation waited for control retransmissions")
	}
	if _, err := conn.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("transport leaked: %v", err)
	}
}

func TestDataFiltersSessionCookieAndLength(t *testing.T) {
	frame := bytes.Repeat([]byte{0xcd}, 64)
	s := &Session{cfg: Config{Version: 3, MTU: 1400, Sublayer: true}, localSession: 123, localCookie: []byte{1, 2, 3, 4}, dataReady: true, frames: make(chan []byte, 8)}
	good := append([]byte{1, 2, 3, 4, 0, 0, 0, 0}, frame...)
	for _, p := range []packet{
		{session: 124, payload: good}, {session: 123, payload: append([]byte{4, 3, 2, 1}, good[4:]...)},
		{session: 123, payload: good[:7]}, {session: 123, payload: append(good, make([]byte, 1500)...)},
	} {
		s.receiveData(p)
	}
	if len(s.frames) != 0 {
		t.Fatal("delivered invalid data packet")
	}
	s.receiveData(packet{session: 123, payload: good})
	select {
	case got := <-s.frames:
		if !bytes.Equal(got, frame) {
			t.Fatal("corrupt Ethernet payload")
		}
	default:
		t.Fatal("valid frame was dropped")
	}
}

func TestSoftEtherPAPEmptyMessageCompatibility(t *testing.T) {
	for _, code := range []byte{2, 3} {
		s := &Session{cfg: Config{Version: 2}, pppState: &pppState{auth: protoPAP, authStarted: true, papID: 1}}
		frame := append([]byte{0xff, 3, 0xc0, 0x23}, cp(code, 1, nil)...)
		err := s.handlePPP(frame)
		if code == 2 && (err != nil || !s.pppState.authenticated || s.Info().Auth != "pap") {
			t.Fatalf("empty PAP ACK: %v", err)
		}
		if code == 3 && !errors.Is(err, ErrAuth) {
			t.Fatalf("empty PAP NAK: %v", err)
		}
	}
}
