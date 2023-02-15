// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package websocket implements a client and server for the WebSocket protocol
// as specified in RFC 6455.
//
// This package currently lacks some features found in an alternative
// and more actively maintained WebSocket package:
//
//	https://pkg.go.dev/nhooyr.io/websocket
package websocket // import "golang.org/x/net/websocket"

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	ProtocolVersionHybi13    = 13
	ProtocolVersionHybi      = ProtocolVersionHybi13
	SupportedProtocolVersion = "13"
)

// ProtocolError represents WebSocket protocol errors.
type ProtocolError struct {
	ErrorString string
}

func (err *ProtocolError) Error() string { return err.ErrorString }

var (
	ErrBadProtocolVersion   = &ProtocolError{"bad protocol version"}
	ErrBadScheme            = &ProtocolError{"bad scheme"}
	ErrBadStatus            = &ProtocolError{"bad status"}
	ErrBadUpgrade           = &ProtocolError{"missing or bad upgrade"}
	ErrBadWebSocketOrigin   = &ProtocolError{"missing or bad WebSocket-Origin"}
	ErrBadWebSocketLocation = &ProtocolError{"missing or bad WebSocket-Location"}
	ErrBadWebSocketProtocol = &ProtocolError{"missing or bad WebSocket-Protocol"}
	ErrBadWebSocketVersion  = &ProtocolError{"missing or bad WebSocket Version"}
	ErrChallengeResponse    = &ProtocolError{"mismatch challenge/response"}
	ErrBadFrame             = &ProtocolError{"bad frame"}
	ErrBadFrameBoundary     = &ProtocolError{"not on frame boundary"}
	ErrNotWebSocket         = &ProtocolError{"not websocket protocol"}
	ErrBadRequestMethod     = &ProtocolError{"bad method"}
	ErrNotSupported         = &ProtocolError{"not supported"}
)

// Config is a WebSocket configuration
type Config struct {
	Host string
	Path string

	// A Websocket client origin.
	OriginUrl string // eg: http://example.com/from/ws

	// WebSocket subprotocols.
	Protocol []string

	// WebSocket protocol version.
	Version int

	// Additional header fields to be sent in WebSocket opening handshake.
	Header http.Header

	handshakeData map[string]string
}

// frameReader is an interface to read a WebSocket frame.
type frameReader interface {
	// Reader is to read payload of the frame.
	io.Reader

	// PayloadType returns payload type.
	PayloadType() opcode
}

// frameReaderFactory is an interface to creates new frame reader.
type frameReaderFactory interface {
	NewFrameReader() (r frameReader, err error)
}

// frameWriter is an interface to write a WebSocket frame.
type frameWriter interface {
	// Writer is to write payload of the frame.
	io.WriteCloser
}

// frameWriterFactory is an interface to create new frame writer.
type frameWriterFactory interface {
	NewFrameWriter(payloadType opcode) (w frameWriter, err error)
}

type frameHandler interface {
	HandleFrame(frame frameReader) (r frameReader, err error)
	WriteClose(status int) (err error)
}

// Conn represents a WebSocket connection.
//
// Multiple goroutines may invoke methods on a Conn simultaneously.
type Conn struct {
	request *http.Request

	buf     *bufio.ReadWriter
	RawConn net.Conn

	rio sync.Mutex
	frameReaderFactory
	frameReader

	wio sync.Mutex
	frameWriterFactory

	frameHandler
	PayloadType        opcode
	defaultCloseStatus int

	// MaxPayloadBytes limits the size of frame payload received over Conn
	// by Codec's Receive method. If zero, DefaultMaxPayloadBytes is used.
	MaxPayloadBytes int
}

// Read implements the io.Reader interface:
// it reads data of a frame from the WebSocket connection.
// if msg is not large enough for the frame data, it fills the msg and next Read
// will read the rest of the frame data.
// it reads Text frame or Binary frame.
func (ws *Conn) Read(msg []byte) (n int, err error) {
	ws.rio.Lock()
	defer ws.rio.Unlock()
again:
	if ws.frameReader == nil {
		frame, err := ws.frameReaderFactory.NewFrameReader()
		if err != nil {
			return 0, err
		}
		ws.frameReader, err = ws.frameHandler.HandleFrame(frame)
		if err != nil {
			return 0, err
		}
		if ws.frameReader == nil {
			goto again
		}
	}
	n, err = ws.frameReader.Read(msg)
	if err == io.EOF {
		ws.frameReader = nil
		goto again
	}
	return n, err
}

// Write implements the io.Writer interface:
// it writes data as a frame to the WebSocket connection.
func (ws *Conn) Write(msg []byte) (n int, err error) {
	ws.wio.Lock()
	defer ws.wio.Unlock()
	w, err := ws.frameWriterFactory.NewFrameWriter(ws.PayloadType)
	if err != nil {
		return 0, err
	}
	n, err = w.Write(msg)
	w.Close()
	return n, err
}

// Close implements the io.Closer interface.
func (ws *Conn) Close() error {
	err := ws.frameHandler.WriteClose(ws.defaultCloseStatus)
	err1 := ws.RawConn.Close()
	if err != nil {
		return err
	}
	return err1
}

// IsClientConn reports whether ws is a client-side connection.
func (ws *Conn) IsClientConn() bool { return ws.request == nil }

// IsServerConn reports whether ws is a server-side connection.
func (ws *Conn) IsServerConn() bool { return ws.request != nil }

func (ws *Conn) LocalAddr() net.Addr  { return ws.RawConn.LocalAddr() }
func (ws *Conn) RemoteAddr() net.Addr { return ws.RawConn.RemoteAddr() }

var errSetDeadline = errors.New("websocket: cannot set deadline: not using a net.Conn")

// SetDeadline sets the connection's network read & write deadlines.
func (ws *Conn) SetDeadline(t time.Time) error { return ws.RawConn.SetDeadline(t) }

// SetReadDeadline sets the connection's network read deadline.
func (ws *Conn) SetReadDeadline(t time.Time) error { return ws.RawConn.SetReadDeadline(t) }

// SetWriteDeadline sets the connection's network write deadline.
func (ws *Conn) SetWriteDeadline(t time.Time) error { return ws.RawConn.SetWriteDeadline(t) }

// Request returns the http request upgraded to the WebSocket.
// It is nil for client side.
func (ws *Conn) Request() *http.Request { return ws.request }
