package websocket

import (
	"bufio"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Conn represents a WebSocket connection.
//
// Multiple goroutines may invoke methods on a Conn simultaneously.
type Conn struct {
	isServer bool

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

	closed    bool
	closeLock sync.Mutex
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
	ws.closeLock.Lock()
	defer ws.closeLock.Unlock()

	if ws.closed {
		return nil
	}

	ws.closed = true
	err := ws.frameHandler.WriteClose(ws.defaultCloseStatus)
	if err1 := ws.RawConn.Close(); err1 != nil {
		err = errors.Join(err, err1)
	}

	if !ws.isServer {
		putBufioReader(ws.buf.Reader)
		putBufioWriter(ws.buf.Writer)
	}
	return err
}
func (ws *Conn) IsServerConn() bool                 { return ws.isServer }
func (ws *Conn) LocalAddr() net.Addr                { return ws.RawConn.LocalAddr() }
func (ws *Conn) RemoteAddr() net.Addr               { return ws.RawConn.RemoteAddr() }
func (ws *Conn) SetDeadline(t time.Time) error      { return ws.RawConn.SetDeadline(t) }
func (ws *Conn) SetReadDeadline(t time.Time) error  { return ws.RawConn.SetReadDeadline(t) }
func (ws *Conn) SetWriteDeadline(t time.Time) error { return ws.RawConn.SetWriteDeadline(t) }
