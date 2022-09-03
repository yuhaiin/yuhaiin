package obfs

import (
	"net"
)

type plain struct{ net.Conn }

func newPlainObfs(conn net.Conn, _ Info) Obfs { return &plain{conn} }
func (p *plain) GetOverhead() int             { return 0 }
