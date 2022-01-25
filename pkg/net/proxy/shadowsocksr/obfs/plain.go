package obfs

import (
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
