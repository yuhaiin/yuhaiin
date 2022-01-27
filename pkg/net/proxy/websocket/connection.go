package websocket

import (
	"errors"
	"io"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"github.com/gorilla/websocket"
)

// connection is a wrapper for net.Conn over WebSocket connection.
type connection struct {
	*websocket.Conn
	reader io.Reader
}

// Read implements net.Conn.Read()
func (c *connection) Read(b []byte) (int, error) {
	for {
		reader, err := c.getReader()
		if err != nil {
			return 0, err
		}

		nBytes, err := reader.Read(b)
		if errors.Is(err, io.EOF) {
			c.reader = nil
			continue
		}
		return nBytes, err
	}
}

func (c *connection) ReadFrom(r io.Reader) (int64, error) {
	buf := utils.GetBytes(2048)
	defer utils.PutBytes(2048, &buf)

	n := int64(0)
	for {
		nr, er := r.Read(buf)
		n += int64(nr)
		_, err := c.Write(buf[:nr])
		if err != nil {
			return n, err
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				return n, nil
			}
			return n, er
		}
	}
}

func (c *connection) getReader() (io.Reader, error) {
	if c.reader != nil {
		return c.reader, nil
	}

	_, reader, err := c.Conn.NextReader()
	if err != nil {
		return nil, err
	}
	c.reader = reader
	return reader, nil
}

// Write implements io.Writer.
func (c *connection) Write(b []byte) (int, error) {
	err := c.Conn.WriteMessage(websocket.BinaryMessage, b)
	return len(b), err
}

func (c *connection) WriteTo(w io.Writer) (int64, error) {
	buf := utils.GetBytes(2048)
	defer utils.PutBytes(2048, &buf)

	n := int64(0)
	for {
		nr, er := c.Read(buf)
		if nr > 0 {
			nw, err := w.Write(buf[:nr])
			n += int64(nw)
			if err != nil {
				return n, err
			}
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				return n, nil
			}
			return n, er
		}
	}
}

func (c *connection) Close() error {
	defer c.Conn.Close()
	return c.Conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second*5))
}

// func (c *connection) LocalAddr() net.Addr {
// 	return c.Conn.LocalAddr()
// }

// func (c *connection) RemoteAddr() net.Addr {
// 	return c.remoteAddr
// }

func (c *connection) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// func (c *connection) SetReadDeadline(t time.Time) error {
// return c.conn.SetReadDeadline(t)
// }

// func (c *connection) SetWriteDeadline(t time.Time) error {
// return c.conn.SetWriteDeadline(t)
// }
