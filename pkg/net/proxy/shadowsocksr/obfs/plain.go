package obfs

import (
	"io"
	"net"
)

type plain struct{ net.Conn }

func newPlainObfs(conn net.Conn, _ Info) Obfs        { return &plain{conn} }
func (p *plain) GetOverhead() int                    { return 0 }
func (p *plain) ReadFrom(r io.Reader) (int64, error) { return io.Copy(p.Conn, r) }
