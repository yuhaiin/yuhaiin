package obfs

import (
	"net"
)

func newPlain(conn net.Conn, _ Obfs) net.Conn { return conn }
