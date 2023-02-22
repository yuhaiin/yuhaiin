// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package websocket

// This file implements a protocol of hybi draft.
// http://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-17

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
)

// Conn represents a WebSocket connection.
//
// Multiple goroutines may invoke methods on a Conn simultaneously.
type Conn struct {
	IsServer bool
	closed   bool

	LastPayloadType opcode
	PayloadType     opcode

	DefaultCloseStatus int

	readHeaderBuf  [8]byte
	writeHeaderBuf [8]byte

	rio     sync.Mutex
	wio     sync.Mutex
	closeMu sync.Mutex

	Rw    *struct{ bufioReadWriter }
	Frame io.Reader

	RawConn net.Conn
}

// newConn creates a new WebSocket connection speaking hybi draft protocol.
func newConn(buf bufioReadWriter, rwc net.Conn, isServer bool) *Conn {
	return &Conn{
		IsServer:           isServer,
		Rw:                 &struct{ bufioReadWriter }{buf},
		RawConn:            rwc,
		PayloadType:        opText,
		DefaultCloseStatus: closeStatusNormal,
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
		if ws.closed {
			return 0, net.ErrClosed
		}

		if ws.Frame == nil {
			ws.rio.Unlock()
			_, ws.Frame, err = ws.NextFrameReader()
			ws.rio.Lock()
			if err != nil {
				return 0, err
			}
		}

		n, err = ws.Frame.Read(msg)
		if err != io.EOF {
			return n, err
		}

		ws.Frame = nil
	}

}

func (ws *Conn) DiscardReader() error {
	ws.rio.Lock()
	defer ws.rio.Unlock()

	if ws.closed {
		return net.ErrClosed
	}

	if ws.Frame != nil {
		_, err := io.Copy(io.Discard, ws.Frame)
		if err != nil {
			return err
		}
		ws.Frame = nil
	}

	return nil
}

func (ws *Conn) NextFrameReader() (*Header, io.Reader, error) {
	ws.rio.Lock()
	defer ws.rio.Unlock()

	for {
		if ws.closed {
			return nil, nil, net.ErrClosed
		}

		header, err := readFrameHeader(ws.Rw, ws.readHeaderBuf[:])
		if err != nil {
			return nil, nil, err
		}

		frame := &frameReader{
			masked:  header.masked,
			maskKey: header.maskKey,
			reader:  io.LimitReader(ws.Rw, header.payloadLength),
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
	ws.wio.Lock()
	defer ws.wio.Unlock()

	if ws.closed {
		return 0, net.ErrClosed
	}

	frameHeader := Header{
		fin:           true,
		opcode:        payloadType,
		masked:        !ws.IsServer,
		payloadLength: int64(len(msg)),
	}

	if frameHeader.masked {
		binary.Read(rand.Reader, binary.BigEndian, &frameHeader.maskKey)
	}

	if err := writeFrameHeader(frameHeader, ws.Rw, ws.writeHeaderBuf[:]); err != nil {
		return 0, err
	}

	if frameHeader.masked {
		buf := pool.GetBytesV2(len(msg))
		defer pool.PutBytesV2(buf)

		copy(buf.Bytes(), msg)

		msg = buf.Bytes()
		mask(frameHeader.maskKey, msg)
	}

	n, err := ws.Rw.Write(msg)
	if err != nil {
		return n, err
	}

	return n, ws.Rw.Flush()
}

func (ws *Conn) handleFrame(header *Header, frame io.Reader) (io.Reader, error) {
	if ws.closed {
		return nil, net.ErrClosed
	}

	if ws.IsServer {
		// The client MUST mask all frames sent to the server.
		if !header.masked {
			ws.WriteClose(closeStatusProtocolError)
			return nil, io.EOF
		}
	} else {
		// The server MUST NOT mask all frames.
		if header.masked {
			ws.WriteClose(closeStatusProtocolError)
			return nil, io.EOF
		}
	}
	switch header.opcode {
	case opContinuation:
		header.opcode = ws.LastPayloadType
	case opText, opBinary:
		ws.LastPayloadType = header.opcode
	case opClose:
		return nil, io.EOF
	case opPing, opPong:
		b := make([]byte, maxControlFramePayloadLength)
		n, err := io.ReadFull(frame, b)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return nil, err
		}
		relay.Copy(io.Discard, frame)
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
	ws.closeMu.Lock()
	defer ws.closeMu.Unlock()

	if ws.closed {
		return nil
	}

	ws.closed = true
	err := ws.WriteClose(ws.DefaultCloseStatus)
	if err1 := ws.RawConn.Close(); err1 != nil {
		err = errors.Join(err, err1)
	}

	if !ws.IsServer {
		if z, ok := ws.Rw.bufioReadWriter.(*bufio.ReadWriter); ok {
			putBufioReader(z.Reader)
			putBufioWriter(z.Writer)
		}
	}

	ws.Rw.bufioReadWriter = &ErrorBufioReadWriter{net.ErrClosed}

	return err
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
