package obfs

import (
	"fmt"
	"net"
	"strings"

	ssr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/utils"
)

type creator func(net.Conn, ssr.ServerInfo) IObfs

var (
	creatorMap = make(map[string]creator)
)

type IObfs interface {
	GetOverhead() int

	net.Conn
}

func register(name string, c creator) {
	creatorMap[name] = c
}

// NewObfs create an obfs object by name and return as an IObfs interface
func newObfs(conn net.Conn, name string, info ssr.ServerInfo) (IObfs, error) {
	c, ok := creatorMap[strings.ToLower(name)]
	if ok {
		return c(conn, info), nil
	}
	return nil, fmt.Errorf("obfs %s not found", name)
}

type Obfs struct {
	name     string
	info     ssr.ServerInfo
	overhead int
	creator  creator
}

func NewObfs(name string, info ssr.ServerInfo) (*Obfs, error) {
	o, ok := creatorMap[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("obfs %s not found", name)
	}

	overhead := o(nil, info).GetOverhead()
	return &Obfs{name, info, overhead, o}, nil
}

func (o *Obfs) Overhead() int {
	return o.overhead
}

func (o *Obfs) StreamObfs(conn net.Conn) net.Conn {
	i := o.info
	return o.creator(conn, i)
}
