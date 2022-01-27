package obfs

import (
	"io"
	"net"

	ssr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/utils"
)

func init() {
	register("plain", newPlainObfs)
}

type plain struct {
	net.Conn
}

func newPlainObfs(conn net.Conn, _ ssr.ServerInfo) IObfs {
	p := &plain{Conn: conn}
	return p
}

func (p *plain) GetOverhead() int {
	return 0
}

func (p *plain) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(p.Conn, r)
}
