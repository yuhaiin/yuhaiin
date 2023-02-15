// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package websocket

// This file implements a protocol of hybi draft.
// http://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-17

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"io"
	"io/ioutil"
	"net"
	"net/http"
)

const (
	websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

	closeStatusNormal            = 1000
	closeStatusGoingAway         = 1001
	closeStatusProtocolError     = 1002
	closeStatusUnsupportedData   = 1003
	closeStatusFrameTooLarge     = 1004
	closeStatusNoStatusRcvd      = 1005
	closeStatusAbnormalClosure   = 1006
	closeStatusBadMessageData    = 1007
	closeStatusPolicyViolation   = 1008
	closeStatusTooBigData        = 1009
	closeStatusExtensionMismatch = 1010

	maxControlFramePayloadLength = 125
)

var (
	ErrBadMaskingKey         = &ProtocolError{"bad masking key"}
	ErrBadPongMessage        = &ProtocolError{"bad pong message"}
	ErrBadClosingStatus      = &ProtocolError{"bad closing status"}
	ErrUnsupportedExtensions = &ProtocolError{"unsupported extensions"}
	ErrNotImplemented        = &ProtocolError{"not implemented"}

	handshakeHeader = map[string]bool{
		"Host":                   true,
		"Upgrade":                true,
		"Connection":             true,
		"Sec-Websocket-Key":      true,
		"Sec-Websocket-Origin":   true,
		"Sec-Websocket-Version":  true,
		"Sec-Websocket-Protocol": true,
		"Sec-Websocket-Accept":   true,
	}
)

// A hybiFrameReader is a reader for hybi frame.
type hybiFrameReader struct {
	reader io.Reader

	header header
}

func (frame *hybiFrameReader) Read(msg []byte) (n int, err error) {
	n, err = frame.reader.Read(msg)
	if frame.header.masked {
		mask(frame.header.maskKey, msg)
	}
	return n, err
}

func (frame *hybiFrameReader) PayloadType() opcode { return frame.header.opcode }

func (frame *hybiFrameReader) TrailerReader() io.Reader { return nil }

// A hybiFrameReaderFactory creates new frame reader based on its frame type.
type hybiFrameReaderFactory struct {
	*bufio.Reader
	readHeaderBuf [8]byte
}

// NewFrameReader reads a frame header from the connection, and creates new reader for the frame.
// See Section 5.2 Base Framing protocol for detail.
// http://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-17#section-5.2
func (buf hybiFrameReaderFactory) NewFrameReader() (frameReader, error) {
	header, err := readFrameHeader(buf.Reader, buf.readHeaderBuf[:])

	return &hybiFrameReader{
		header: header,
		reader: io.LimitReader(buf.Reader, header.payloadLength),
	}, err
}

// A HybiFrameWriter is a writer for hybi frame.
type hybiFrameWriter struct {
	writer         *bufio.Writer
	writeHeaderBuf [8]byte
	header         *header
}

func (frame *hybiFrameWriter) Write(msg []byte) (n int, err error) {
	frame.header.payloadLength = int64(len(msg))
	if err = writeFrameHeader(*frame.header, frame.writer, frame.writeHeaderBuf[:]); err != nil {
		return 0, err
	}

	if frame.header.masked {
		mask(frame.header.maskKey, msg)
	}

	frame.writer.Write(msg)
	err = frame.writer.Flush()
	return len(msg), err
}

func (frame *hybiFrameWriter) Close() error { return nil }

type hybiFrameWriterFactory struct {
	*bufio.Writer
	needMaskingKey bool
}

func (buf hybiFrameWriterFactory) NewFrameWriter(payloadType opcode) (frame frameWriter, err error) {
	frameHeader := &header{fin: true, opcode: payloadType}
	if buf.needMaskingKey {
		frameHeader.masked = true
		binary.Read(rand.Reader, binary.BigEndian, frameHeader.maskKey)
	}
	return &hybiFrameWriter{writer: buf.Writer, header: frameHeader}, nil
}

type hybiFrameHandler struct {
	conn        *Conn
	payloadType opcode
}

func (handler *hybiFrameHandler) HandleFrame(frame frameReader) (frameReader, error) {
	if handler.conn.IsServerConn() {
		// The client MUST mask all frames sent to the server.
		if !frame.(*hybiFrameReader).header.masked {
			handler.WriteClose(closeStatusProtocolError)
			return nil, io.EOF
		}
	} else {
		// The server MUST NOT mask all frames.
		if frame.(*hybiFrameReader).header.masked {
			handler.WriteClose(closeStatusProtocolError)
			return nil, io.EOF
		}
	}
	// if header := frame.HeaderReader(); header != nil {
	// 	io.Copy(ioutil.Discard, header)
	// }
	switch frame.PayloadType() {
	case opContinuation:
		frame.(*hybiFrameReader).header.opcode = handler.payloadType
	case opText, opBinary:
		handler.payloadType = frame.PayloadType()
	case opClose:
		return nil, io.EOF
	case opPing, opPong:
		b := make([]byte, maxControlFramePayloadLength)
		n, err := io.ReadFull(frame, b)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return nil, err
		}
		io.Copy(ioutil.Discard, frame)
		if frame.PayloadType() == opPing {
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
	if buf == nil {
		br := bufio.NewReader(rwc)
		bw := bufio.NewWriter(rwc)
		buf = bufio.NewReadWriter(br, bw)
	}
	ws := &Conn{
		request:            request,
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

// getNonceAccept computes the base64-encoded SHA-1 of the concatenation of
// the nonce ("Sec-WebSocket-Key" value) with the websocket GUID string.
func getNonceAccept(nonce []byte) (expected []byte, err error) {
	h := sha1.New()
	if _, err = h.Write(nonce); err != nil {
		return
	}
	if _, err = h.Write([]byte(websocketGUID)); err != nil {
		return
	}
	expected = make([]byte, 28)
	base64.StdEncoding.Encode(expected, h.Sum(nil))
	return
}
