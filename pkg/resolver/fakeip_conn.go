package resolver

import "errors"

// Half-closing a leased stream must preserve the opposite direction and keep
// its mapping pinned until the stream owner closes the whole connection.
func (c *leasedFakeIPConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return c.Close()
}

func (c *leasedFakeIPConn) CloseRead() error {
	if conn, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return conn.CloseRead()
	}
	return errors.ErrUnsupported
}
