package obfs

import (
	"fmt"
	"net"

	ssr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/utils"
)

var ObfsMethod = map[string]func(net.Conn, Info) Obfs{
	"http_post":              newHttpPost,
	"http_simple":            newHttpSimple,
	"plain":                  newPlainObfs,
	"random_head":            newRandomHead,
	"tls1.2_ticket_auth":     newTLS12TicketAuth,
	"tls1.2_ticket_fastauth": newTLS12TicketAuth,
}

type Obfs interface {
	GetOverhead() int
	net.Conn
}

type Info struct {
	ssr.Info
	Name  string
	Host  string
	Port  uint16
	Param string
}

func (o *Info) creator() (func(net.Conn, Info) Obfs, error) {
	z, ok := ObfsMethod[o.Name]
	if !ok {
		return nil, fmt.Errorf("obfs %s not found", o.Name)
	}

	return z, nil
}
func (o *Info) Stream(c net.Conn) (net.Conn, error) {
	cc, err := o.creator()
	if err != nil {
		return nil, err
	}
	return cc(c, *o), nil
}

func (o *Info) Overhead() int {
	cc, err := o.creator()
	if err != nil {
		return -1
	}
	return cc(nil, *o).GetOverhead()
}
