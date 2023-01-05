package obfs

import (
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/cipher"
)

var ObfsMethod = map[string]struct {
	overhead int
	stream   func(net.Conn, Obfs) net.Conn
}{
	"http_post":              {0, newHttpPost},
	"http_simple":            {0, newHttpSimple},
	"plain":                  {0, newPlain},
	"random_head":            {0, newRandomHead},
	"tls1.2_ticket_auth":     {5, newTLS12TicketAuth},
	"tls1.2_ticket_fastauth": {5, newTLS12TicketAuth},
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
