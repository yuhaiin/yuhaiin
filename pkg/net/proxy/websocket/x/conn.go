// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package websocket

// This file implements a protocol of hybi draft.
// http://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-17

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
)

// Conn represents a WebSocket connection.
//
// Multiple goroutines may invoke methods on a Conn simultaneously.
type Conn struct {
	IsServer bool

	LastPayloadType opcode
	PayloadType     opcode

	readHeaderBuf  [8]byte
	writeHeaderBuf [8]byte

	rio sync.Mutex
	wio sync.Mutex

	Frame io.ReadCloser

	RawConn net.Conn
}

// newConn creates a new WebSocket connection speaking hybi draft protocol.
func newConn(rwc net.Conn, isServer bool) *Conn {
	return &Conn{
		IsServer:    isServer,
		RawConn:     rwc,
		PayloadType: opBinary,
	}
}

// Read implements the io.Reader interface:
// it reads data of a frame from the WebSocket connection.
// if msg is not large enough for the frame data, it fills the msg and next Read
// will read the rest of the frame data.
// it reads Text frame or Binary frame.
func (ws *Conn) Read(msg []byte) (n int, err error) {
	ws.rio.Lock()
	defer ws.rio.Unlock()

	for {
		if ws.Frame == nil {
			_, ws.Frame, err = ws.nextFrameReader()
			if err != nil {
				return 0, err
			}
		}

		n, err = ws.Frame.Read(msg)
		if err == nil || n != 0 {
			return n, err
		}

		if !errors.Is(err, io.EOF) {
			return n, err
		}

		ws.Frame = nil
	}

}

func (ws *Conn) NextFrameReader(handle func(*Header, io.ReadCloser) error) error {
	ws.rio.Lock()
	defer ws.rio.Unlock()

	if ws.Frame != nil {
		_ = ws.Frame.Close()
		ws.Frame = nil
	}

	h, r, err := ws.nextFrameReader()
	if err != nil {
		return err
	}
	defer r.Close()

	if err := handle(h, r); err != nil {
		return err
	}

	return nil
}

func (ws *Conn) nextFrameReader() (*Header, io.ReadCloser, error) {
	for {
		header, err := readFrameHeader(netapi.NewReader(ws.RawConn), ws.readHeaderBuf[:])
		if err != nil {
			return nil, nil, err
		}

		frame := &frameReader{
			masked:  header.masked,
			maskKey: header.maskKey,
			reader:  io.LimitReader(ws.RawConn, header.payloadLength),
		}

		frameReader, err := ws.handleFrame(&header, frame)
		if err != nil {
			return nil, nil, err
		}

		if frameReader != nil {
			return &header, frameReader, nil
		}
	}
}

// Write implements the io.Writer interface:
// it writes data as a frame to the WebSocket connection.
func (ws *Conn) Write(msg []byte) (n int, err error) { return ws.WriteMsg(msg, ws.PayloadType) }

func (ws *Conn) WriteMsg(msg []byte, payloadType opcode) (int, error) {
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)

	frameHeader := Header{
		fin:           true,
		opcode:        payloadType,
		masked:        !ws.IsServer,
		payloadLength: int64(len(msg)),
	}

	if frameHeader.masked {
		_ = binary.Read(rand.Reader, binary.BigEndian, &frameHeader.maskKey)
	}

	if err := writeFrameHeader(frameHeader, buf, ws.writeHeaderBuf[:]); err != nil {
		return 0, err
	}

	headerLength := buf.Len()

	buf.Write(msg)

	if frameHeader.masked {
		mask(frameHeader.maskKey, buf.Bytes()[headerLength:])
	}

	ws.wio.Lock()
	n, err := ws.RawConn.Write(buf.Bytes())
	ws.wio.Unlock()
	if err != nil {
		return n, err
	}

	return int(frameHeader.payloadLength), nil
}

func (ws *Conn) handleFrame(header *Header, frame io.ReadCloser) (io.ReadCloser, error) {
	if ws.IsServer && !header.masked {
		// client --> server
		// The client MUST mask all frames sent to the server.
		ws.WriteClose(closeStatusProtocolError)
		return nil, io.EOF
	} else if !ws.IsServer && header.masked {
		// server --> client
		// The server MUST NOT mask all frames.
		ws.WriteClose(closeStatusProtocolError)
		return nil, io.EOF
	}

	switch header.opcode {
	case opContinuation:
		header.opcode = ws.LastPayloadType
	case opText, opBinary:
		ws.LastPayloadType = header.opcode
	case opClose:
		ws.Close()
		return nil, io.EOF
	case opPing, opPong:
		b := make([]byte, maxControlFramePayloadLength)
		n, err := io.ReadFull(frame, b)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return nil, err
		}
		_ = frame.Close()
		if header.opcode == opPing {
			if _, err := ws.WritePong(b[:n]); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	return frame, nil
}

func (ws *Conn) WriteClose(status int) (err error) {
	_, err = ws.WriteMsg(binary.BigEndian.AppendUint16(nil, uint16(status)), opClose)
	return err
}

func (ws *Conn) WritePong(msg []byte) (n int, err error) { return ws.WriteMsg(msg, opPong) }

// Close implements the io.Closer interface.
func (ws *Conn) Close() error {
	return ws.RawConn.Close()
}

func (ws *Conn) LocalAddr() net.Addr                { return ws.RawConn.LocalAddr() }
func (ws *Conn) RemoteAddr() net.Addr               { return ws.RawConn.RemoteAddr() }
func (ws *Conn) SetDeadline(t time.Time) error      { return ws.RawConn.SetDeadline(t) }
func (ws *Conn) SetReadDeadline(t time.Time) error  { return ws.RawConn.SetReadDeadline(t) }
func (ws *Conn) SetWriteDeadline(t time.Time) error { return ws.RawConn.SetWriteDeadline(t) }

// A frameReader is a reader for hybi frame.
type frameReader struct {
	reader io.Reader

	masked  bool
	maskKey uint32
}

func (frame *frameReader) Read(msg []byte) (n int, err error) {
	n, err = frame.reader.Read(msg)
	if frame.masked {
		frame.maskKey = mask(frame.maskKey, msg[:n])
	}
	return n, err
}

func (f *frameReader) Close() error {
	_, err := relay.Copy(io.Discard, f.reader)
	return err
}
