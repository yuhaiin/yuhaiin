package obfs

import (
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/cipher"
)

var ObfsMethod = map[string]struct {
	stream   func(net.Conn, Obfs) net.Conn
	overhead int
}{
	"http_post":              {newHttpPost, 0},
	"http_simple":            {newHttpSimple, 0},
	"plain":                  {newPlain, 0},
	"random_head":            {newRandomHead, 0},
	"tls1.2_ticket_auth":     {newTLS12TicketAuth, 5},
	"tls1.2_ticket_fastauth": {newTLS12TicketAuth, 5},
}

type Obfs struct {
	*cipher.Cipher
	Name  string
	Host  string
	Port  string
	Param string
}

func (o Obfs) Stream(c net.Conn) (net.Conn, error) {
	z, ok := ObfsMethod[o.Name]
	if !ok {
		return nil, fmt.Errorf("obfs %s not found", o.Name)
	}
	return z.stream(c, o), nil
}

func (o Obfs) Overhead() int {
	z, ok := ObfsMethod[o.Name]
	if !ok {
		return -1
	}
	return z.overhead
}
