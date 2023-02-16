// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package websocket

// This file implements a protocol of hybi draft.
// http://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-17

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"net/http"
)

type hybiFrameHandler struct {
	conn        *Conn
	payloadType opcode
}

func (handler *hybiFrameHandler) HandleFrame(frame frameReader) (frameReader, error) {
	if handler.conn.isServer {
		// The client MUST mask all frames sent to the server.
		if !frame.Header().masked {
			handler.WriteClose(closeStatusProtocolError)
			return nil, io.EOF
		}
	} else {
		// The server MUST NOT mask all frames.
		if frame.Header().masked {
			handler.WriteClose(closeStatusProtocolError)
			return nil, io.EOF
		}
	}
	switch frame.Header().opcode {
	case opContinuation:
		frame.Header().opcode = handler.payloadType
	case opText, opBinary:
		handler.payloadType = frame.Header().opcode
	case opClose:
		return nil, io.EOF
	case opPing, opPong:
		b := make([]byte, maxControlFramePayloadLength)
		n, err := io.ReadFull(frame, b)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return nil, err
		}
		io.Copy(io.Discard, frame)
		if frame.Header().opcode == opPing {
			if _, err := handler.WritePong(b[:n]); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	return frame, nil
}

func (handler *hybiFrameHandler) WriteClose(status int) (err error) {
	handler.conn.wio.Lock()
	defer handler.conn.wio.Unlock()
	w, err := handler.conn.frameWriterFactory.NewFrameWriter(opClose)
	if err != nil {
		return err
	}
	msg := make([]byte, 2)
	binary.BigEndian.PutUint16(msg, uint16(status))
	_, err = w.Write(msg)
	w.Close()
	return err
}

func (handler *hybiFrameHandler) WritePong(msg []byte) (n int, err error) {
	handler.conn.wio.Lock()
	defer handler.conn.wio.Unlock()
	w, err := handler.conn.frameWriterFactory.NewFrameWriter(opPong)
	if err != nil {
		return 0, err
	}
	n, err = w.Write(msg)
	w.Close()

	return n, err
}

// newHybiConn creates a new WebSocket connection speaking hybi draft protocol.
func newHybiConn(buf *bufio.ReadWriter, rwc net.Conn, request *http.Request) *Conn {
	ws := &Conn{
		isServer:           request != nil,
		buf:                buf,
		RawConn:            rwc,
		frameReaderFactory: hybiFrameReaderFactory{Reader: buf.Reader},
		frameWriterFactory: hybiFrameWriterFactory{
			Writer:         buf.Writer,
			needMaskingKey: request == nil,
		},
		PayloadType:        opText,
		defaultCloseStatus: closeStatusNormal,
	}
	ws.frameHandler = &hybiFrameHandler{conn: ws}
	return ws
}
