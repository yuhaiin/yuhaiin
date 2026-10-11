package http3

// An HTTP/3 connection over one QUIC connection, reduced to what CONNECT needs.
//
// After the QUIC handshake, HTTP/3 requires each side to open a unidirectional
// control stream and send SETTINGS before anything else. veepin opens that, plus
// the two QPACK streams (which stay empty, since the encoder never uses the
// dynamic table), and runs one accept loop that classifies incoming streams: the
// peer's control stream feeds its SETTINGS in, its QPACK streams are drained and
// ignored, and an incoming bidirectional stream is a CONNECT request for the
// server side to pick up.
//
// The one ordering rule that matters: a client must not send an Extended CONNECT
// until it has seen the server advertise SETTINGS_ENABLE_CONNECT_PROTOCOL.
// OpenConnect blocks on that, so the caller cannot get it wrong.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/net/quic"
)

// Conn is an HTTP/3 connection.
type Conn struct {
	qc       *quic.Conn
	isClient bool

	settingsOnce sync.Once
	settingsCh   chan struct{} // closed once peerSettings (or peerErr) is set
	mu           sync.Mutex
	peerSettings Settings
	peerErr      error

	incoming chan *RequestStream // server: CONNECT request streams
}

// Client performs the HTTP/3 setup as the initiator over an established QUIC
// connection: opens the control and QPACK streams, sends SETTINGS, and starts
// reading the peer's streams.
func Client(ctx context.Context, qc *quic.Conn) (*Conn, error) {
	return newConn(ctx, qc, true)
}

// Server performs the HTTP/3 setup as the responder. AcceptConnect then yields
// incoming CONNECT request streams.
func Server(ctx context.Context, qc *quic.Conn) (*Conn, error) {
	return newConn(ctx, qc, false)
}

func newConn(ctx context.Context, qc *quic.Conn, isClient bool) (*Conn, error) {
	c := &Conn{
		qc:         qc,
		isClient:   isClient,
		settingsCh: make(chan struct{}),
		incoming:   make(chan *RequestStream, 8),
	}

	// Control stream: type byte, then SETTINGS. This must be the first thing the
	// peer sees on a control stream, so it is written before anything else.
	ctrl, err := qc.NewSendOnlyStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("http3: opening control stream: %w", err)
	}
	if _, err := ctrl.Write(AppendVarint(nil, StreamControl)); err != nil {
		return nil, err
	}
	if err := WriteFrame(ctrl, FrameSettings, DefaultSettings().Encode()); err != nil {
		return nil, err
	}
	if err := ctrl.Flush(); err != nil {
		return nil, err
	}

	// QPACK encoder and decoder streams. They carry no instructions here, but a
	// strict peer expects them to exist, so each is opened with just its type.
	for _, typ := range []uint64{StreamQPACKEncoder, StreamQPACKDecoder} {
		s, err := qc.NewSendOnlyStream(ctx)
		if err != nil {
			return nil, fmt.Errorf("http3: opening QPACK stream: %w", err)
		}
		if _, err := s.Write(AppendVarint(nil, typ)); err != nil {
			return nil, err
		}
		if err := s.Flush(); err != nil {
			return nil, err
		}
	}

	go c.acceptLoop()
	return c, nil
}

// acceptLoop classifies every incoming stream for the life of the connection.
func (c *Conn) acceptLoop() {
	for {
		s, err := c.qc.AcceptStream(context.Background())
		if err != nil {
			c.failSettings(err)
			close(c.incoming)
			return
		}
		if s.IsReadOnly() {
			go c.handleUniStream(s)
			continue
		}
		// A bidirectional stream from the peer is a request. Only the server
		// role expects these; a client that receives one lets it drop.
		if !c.isClient {
			select {
			case c.incoming <- &RequestStream{qs: s}:
			default:
				// Shed, not served: the stream is being dropped whatever
				// Reset reports, and its only failure is a stream with no
				// send side, which a bidirectional one has.
				_ = s.Reset(quic_H3_EXCESSIVE_LOAD)
			}
		}
	}
}

// quic_H3_EXCESSIVE_LOAD is H3_EXCESSIVE_LOAD (RFC 9114 §8.1), used to shed a
// request the server cannot queue.
const quic_H3_EXCESSIVE_LOAD = 0x0107

// handleUniStream reads the type of a peer unidirectional stream and dispatches
// it. Only the control stream is acted on; the QPACK streams are drained so the
// peer's flow control is not stalled, and any other type is ignored.
func (c *Conn) handleUniStream(s *quic.Stream) {
	typ, err := ReadVarint(s)
	if err != nil {
		return
	}
	switch typ {
	case StreamControl:
		c.readControl(s)
	default:
		// QPACK streams and anything else: consume and discard.
		_, _ = io.Copy(io.Discard, s)
	}
}

// readControl reads the peer's SETTINGS from its control stream. The first frame
// on a control stream must be SETTINGS (RFC 9114 §7.2.4); anything else is a
// connection error, surfaced through the settings gate so OpenConnect fails
// rather than hanging.
func (c *Conn) readControl(s *quic.Stream) {
	typ, payload, err := ReadFrame(s)
	if err != nil {
		c.failSettings(err)
		return
	}
	if typ != FrameSettings {
		c.failSettings(fmt.Errorf("http3: first control frame is %#x, not SETTINGS", typ))
		return
	}
	settings, err := ParseSettings(payload)
	if err != nil {
		c.failSettings(err)
		return
	}
	c.mu.Lock()
	c.peerSettings = settings
	c.mu.Unlock()
	c.settingsOnce.Do(func() { close(c.settingsCh) })

	// Later frames on the control stream (a peer may send more SETTINGS-adjacent
	// control frames) are drained; none of them affect a CONNECT tunnel.
	_, _ = io.Copy(io.Discard, s)
}

func (c *Conn) failSettings(err error) {
	c.mu.Lock()
	if c.peerErr == nil {
		c.peerErr = err
	}
	c.mu.Unlock()
	c.settingsOnce.Do(func() { close(c.settingsCh) })
}

// awaitSettings blocks until the peer's SETTINGS have arrived or the context is
// done.
func (c *Conn) awaitSettings(ctx context.Context) (Settings, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.settingsCh:
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.peerErr != nil {
		return nil, c.peerErr
	}
	return c.peerSettings, nil
}

// ErrNoConnectProtocol reports a server that does not permit Extended CONNECT.
var ErrNoConnectProtocol = errors.New("http3: peer does not advertise ENABLE_CONNECT_PROTOCOL")

// OpenConnect opens a request stream and sends an Extended CONNECT with the
// given header fields, after confirming the server permits it. The returned
// stream carries capsules once WriteResponse has been read.
func (c *Conn) OpenConnect(ctx context.Context, fields []Field) (*RequestStream, error) {
	settings, err := c.awaitSettings(ctx)
	if err != nil {
		return nil, err
	}
	if !settings.ConnectProtocolEnabled() {
		return nil, ErrNoConnectProtocol
	}

	s, err := c.qc.NewStream(ctx)
	if err != nil {
		return nil, err
	}
	if err := WriteFrame(s, FrameHeaders, EncodeFieldSection(fields)); err != nil {
		return nil, err
	}
	if err := s.Flush(); err != nil {
		return nil, err
	}
	return &RequestStream{qs: s}, nil
}

// AcceptConnect returns the next incoming CONNECT request stream and its header
// fields. It is the server counterpart to OpenConnect.
func (c *Conn) AcceptConnect(ctx context.Context) (*RequestStream, []Field, error) {
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case rs, ok := <-c.incoming:
		if !ok {
			return nil, nil, io.EOF
		}
		fields, err := rs.readHeaders()
		if err != nil {
			return nil, nil, err
		}
		return rs, fields, nil
	}
}

// Close tears down the QUIC connection.
func (c *Conn) Close() error { return c.qc.Close() }
