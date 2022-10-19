package obfs

import (
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/cipher"
)

var ObfsMethod = map[string]func(net.Conn, Obfs) obfs{
	"http_post":              newHttpPost,
	"http_simple":            newHttpSimple,
	"plain":                  newPlainObfs,
	"random_head":            newRandomHead,
	"tls1.2_ticket_auth":     newTLS12TicketAuth,
	"tls1.2_ticket_fastauth": newTLS12TicketAuth,
}

type obfs interface {
	GetOverhead() int
	net.Conn
}

type Obfs struct {
	*cipher.Cipher
	Name  string
	Host  string
	Port  string
	Param string
}

func (o *Obfs) creator() (func(net.Conn, Obfs) obfs, error) {
	z, ok := ObfsMethod[o.Name]
	if !ok {
		return nil, fmt.Errorf("obfs %s not found", o.Name)
	}

	return z, nil
}
func (o *Obfs) Stream(c net.Conn) (net.Conn, error) {
	cc, err := o.creator()
	if err != nil {
		return nil, err
	}
	return cc(c, *o), nil
}

func (o *Obfs) Overhead() int {
	cc, err := o.creator()
	if err != nil {
		return -1
	}
	return cc(nil, *o).GetOverhead()
}
