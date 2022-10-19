package obfs

import (
	"net"
)

type plain struct{ net.Conn }

func newPlainObfs(conn net.Conn, _ Obfs) obfs { return &plain{conn} }
func (p *plain) GetOverhead() int             { return 0 }
